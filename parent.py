import json
import math
import os
import resource
import signal
import time
from dataclasses import asdict, dataclass

import click
import landlock
import prctl

VERSION = "23.1002"


@click.command(
    help=f"Run program with parent version {VERSION}.",
    context_settings={
        "allow_interspersed_args": False,
    },
)
@click.option(
    "-m",
    "--memory",
    type=int,
    help="The program's maximum memory address space in kilobytes.",
)
@click.option(
    "-t",
    "--cpu-time",
    type=int,
    help="The program's maximum CPU time in milliseconds.",
)
@click.option(
    "-r",
    "--real-time",
    type=int,
    help="The program's maximum real-time execution time in milliseconds.",
)
@click.option("--stack", type=int, help="The program's stack size limit in kilobytes.")
@click.option(
    "-f",
    "--file-size",
    type=int,
    help="The program's maximum file size in kilobytes that it can create or modify.",
)
@click.option(
    "-p",
    "--processes",
    type=int,
    help="The number of threads, or processes, the program can use.",
)
@click.option(
    "--stdin",
    help="Redirect a file to the program's stdin.",
    type=click.Path(exists=True, dir_okay=False, readable=True),
)
@click.option(
    "--stdout",
    help="Redirect the program's stdout to a file.",
    type=click.Path(dir_okay=False, writable=True),
)
@click.option(
    "--stderr",
    help="Redirect the program's stderr to a file.",
    type=click.Path(dir_okay=False, writable=True),
)
@click.option(
    "--stderr-to-stdout", help="Redirect the program's stderr to stdout.", is_flag=True
)
@click.option(
    "-s",
    "--stats",
    help="Save execution statistics to a file.",
    type=click.File(mode="w"),
)
@click.option(
    "--fs-readonly",
    help="Allow the program read from files located under the provided path.",
    multiple=True,
)
@click.option(
    "--fs-readwrite",
    help="Allow the program write to files located under the provided path.",
    multiple=True,
)
@click.option(
    "--env", help="Set an environment variable.", type=(str, str), multiple=True
)
@click.option("--empty-env", help="Do not inherit parent's environment.", is_flag=True)
@click.option("--drop-caps", help="Drop the program's capabilities.", is_flag=True)
@click.argument("program")
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def run(stats, **kwargs):
    pid = os.fork()
    if pid == 0:  # Child process
        child(**kwargs)
    else:
        run_stats = parent(pid, **kwargs)
        if stats:
            json.dump(asdict(run_stats), stats)
        exit(run_stats.exit_code)


@dataclass
class RunStats:
    exit_code: int
    max_rss: int
    cpu_time: int
    real_time: int
    timeouted: bool


def parent(pid, real_time, cpu_time, **_) -> RunStats:
    def kill_child(sig, frame):
        os.kill(pid, signal.SIGKILL)

    if real_time:
        signal.signal(signal.SIGALRM, kill_child)
        signal.setitimer(signal.ITIMER_REAL, real_time / 1000)

    start = time.time()
    _, exitstatus = os.waitpid(pid, 0)
    duration = time.time() - start
    exit_code = os.waitstatus_to_exitcode(exitstatus)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)

    cpu_time_ms = int(usage.ru_utime * 1000)
    duration_ms = int(duration * 1000)
    max_rss_kilobytes = int(usage.ru_maxrss * 1.024)  # rusage is in KiB

    timeouted = False
    if real_time and duration_ms >= real_time:
        timeouted = True
    if cpu_time and cpu_time_ms >= cpu_time:
        timeouted = True

    return RunStats(exit_code, max_rss_kilobytes, cpu_time_ms, duration_ms, timeouted)


def child(
    memory,
    stack,
    cpu_time,
    file_size,
    processes,
    program,
    args,
    stdin,
    stdout,
    stderr,
    stderr_to_stdout,
    fs_readonly,
    fs_readwrite,
    env,
    empty_env,
    drop_caps,
    **_,
):
    if memory:
        memory_bytes = memory * 1000
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    if stack and stack > 0:
        stack_bytes = stack * 1000
        resource.setrlimit(resource.RLIMIT_STACK, (stack_bytes, stack_bytes))
    elif stack < 0:
        resource.setrlimit(
            resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        )

    if cpu_time:
        cpu_time_secs = math.ceil(cpu_time / 1000)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_time_secs, cpu_time_secs))

    if file_size:
        file_size_bytes = file_size * 1000
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_bytes, file_size_bytes))

    if processes:
        resource.setrlimit(resource.RLIMIT_NPROC, (processes, processes))

    # disable core dumps
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    # file access limit
    if fs_readonly or fs_readwrite:
        rs = landlock.Ruleset()
        if fs_readonly:
            rs.allow(
                *fs_readonly,
                rules=landlock.FSAccess.READ_FILE
                | landlock.FSAccess.READ_DIR
                | landlock.FSAccess.EXECUTE,
            )
        if fs_readwrite:
            rs.allow(*fs_readwrite)
        rs.apply()

    # drop all capabilities
    if drop_caps:
        prctl.cap_permitted.limit()
        prctl.cap_inheritable.limit()
        prctl.cap_effective.limit()
        prctl.set_no_new_privs(1)

    if stdin:
        fh = os.open(stdin, os.O_RDONLY)
        os.dup2(fh, 0)
        os.close(fh)

    if stdout:
        fh = os.open(stdout, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.dup2(fh, 1)
        os.close(fh)

    if stderr:
        fh = os.open(stderr, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.dup2(fh, 2)
        os.close(fh)

    if stderr_to_stdout:
        os.dup2(1, 2)

    process_env = {}
    if not empty_env:
        process_env.update(os.environ)
    process_env.update({k: v for k, v in env})

    print("start", process_env)
    os.execve(program, (os.path.basename(program),) + args, process_env)
