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
import pyseccomp as seccomp

VERSION = "25.2"


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
    help="Allow the program read from files or folder located under the provided path.",
    multiple=True,
)
@click.option(
    "--fs-writeonly",
    help="Allow the program write to files or folders located under the provided path.",
    multiple=True,
)
@click.option(
    "--fs-readwrite",
    help="Allow the program read or write to files or folders located under the provided path.",
    multiple=True,
)
@click.option(
    "--env", help="Set an environment variable.", type=(str, str), multiple=True
)
@click.option("--empty-env", help="Do not inherit parent's environment.", is_flag=True)
@click.option("--drop-caps", help="Drop the program's capabilities.", is_flag=True)
@click.option(
    "--seccomp-default",
    help="Default policy for syscalls (when not set, kill is denied).",
    type=click.Choice(["allow", "deny", "kill", "none"], case_sensitive=False),
)
@click.option(
    "--seccomp-allow",
    help="Deny syscall.",
    multiple=True,
)
@click.option(
    "--seccomp-deny",
    help="Deny syscall.",
    multiple=True,
)
@click.option(
    "--seccomp-kill",
    help="Kill program on that syscall.",
    multiple=True,
)
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
    elif cpu_time and cpu_time_ms >= cpu_time:
        timeouted = True
    elif os.WIFSIGNALED(exitstatus) and os.WTERMSIG(exitstatus) == 9:
        # if process was killed, add 2% tolerance (minimum of 15ms)
        # to compensate errors in time measuring
        if real_time and max(duration_ms * 1.02, duration_ms + 0.015) >= real_time:
            timeouted = True
        elif cpu_time and max(cpu_time_ms * 1.02, duration_ms + 0.015) >= cpu_time:
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
    fs_writeonly,
    fs_readwrite,
    env,
    empty_env,
    drop_caps,
    seccomp_default,
    seccomp_allow,
    seccomp_deny,
    seccomp_kill,
    **_,
):
    if memory:
        memory_bytes = memory * 1000
        resource.setrlimit(resource.RLIMIT_DATA, (memory_bytes, memory_bytes))

    if stack:
        if stack > 0:
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

    # seccomp syscall filtering
    if seccomp_default != "none":
        syscall_filter = seccomp.SyscallFilter(
            defaction=getattr(seccomp, seccomp_default.upper())
            if seccomp_default
            else seccomp.ALLOW
        )

        if seccomp_default is None:
            syscall_filter.add_rule(seccomp.ERRNO(1), "kill")

        else:
            for syscall in seccomp_allow:
                syscall_filter.add_rule(seccomp.ALLOW, syscall)

            for syscall in seccomp_deny:
                syscall_filter.add_rule(seccomp.ERRNO(1), syscall)

            for syscall in seccomp_kill:
                syscall_filter.add_rule(seccomp.KILL_PROCESS, syscall)

        syscall_filter.load()

    # open needed files before restricting file access
    stdin_fh, stdout_fh, stderr_fh = None, None, None

    if stdin:
        stdin_fh = os.open(stdin, os.O_RDONLY)

    if stdout:
        stdout_fh = os.open(stdout, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)

    if stderr:
        stderr_fh = os.open(stderr, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)

    # file access limit
    if fs_readonly or fs_writeonly or fs_readwrite:
        rs = landlock.Ruleset()
        if fs_readonly:
            files = []
            dirs = []
            for path in fs_readonly:
                if os.path.isdir(path):
                    dirs.append(path)
                else:
                    files.append(path)

            rules = landlock.FSAccess.READ_FILE | landlock.FSAccess.EXECUTE

            rs.allow(*files, rules=rules)
            # append read_dir for directories only, else it would break for files
            rs.allow(*dirs, rules=rules | landlock.FSAccess.READ_DIR)

        if fs_writeonly:
            files = []
            dirs = []
            for path in fs_writeonly:
                if os.path.isdir(path):
                    dirs.append(path)
                else:
                    files.append(path)

            rules = landlock.FSAccess.WRITE_FILE

            rs.allow(*files, rules=rules)
            rs.allow(
                *dirs,
                rules=rules
                | landlock.FSAccess.READ_DIR
                | landlock.FSAccess.REMOVE_DIR
                | landlock.FSAccess.REMOVE_FILE
                | landlock.FSAccess.MAKE_DIR
                | landlock.FSAccess.MAKE_REG,
            )

        if fs_readwrite:
            files = []
            dirs = []
            for path in fs_readwrite:
                if os.path.isdir(path):
                    dirs.append(path)
                else:
                    files.append(path)

            rules = (
                landlock.FSAccess.READ_FILE
                | landlock.FSAccess.EXECUTE
                | landlock.FSAccess.WRITE_FILE
            )

            rs.allow(*files, rules=rules)
            rs.allow(
                *dirs,
                rules=rules
                | landlock.FSAccess.READ_DIR
                | landlock.FSAccess.REMOVE_DIR
                | landlock.FSAccess.REMOVE_FILE
                | landlock.FSAccess.MAKE_DIR
                | landlock.FSAccess.MAKE_REG,
            )

        rs.apply()

    # drop all capabilities
    if drop_caps:
        prctl.cap_permitted.limit()
        prctl.cap_inheritable.limit()
        prctl.cap_effective.limit()
        prctl.set_no_new_privs(1)

    # redirect streams
    if stdin and stdin_fh:
        os.dup2(stdin_fh, 0)
        os.close(stdin_fh)

    if stdout and stdout_fh:
        os.dup2(stdout_fh, 1)
        os.close(stdout_fh)

    if stderr and stderr_fh:
        os.dup2(stderr_fh, 2)
        os.close(stderr_fh)

    if stderr_to_stdout:
        os.dup2(1, 2)

    process_env = {}
    if not empty_env:
        process_env.update(os.environ)
    process_env.update({k: v for k, v in env})

    os.execve(program, (os.path.basename(program),) + args, process_env)
