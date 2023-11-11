import json
import math
import os
import resource
import signal
import time
from dataclasses import dataclass, asdict

import click
import pyprctl


VERSION = "23.1002"


@click.command(help=f"Run program with parent version {VERSION}.")
@click.option("-m", "--memory", type=int, help="Memory address space limit of the program in kB.")
@click.option("-t", "--cpu-time", type=int, help="Limit the amount of CPU time the program can use in milliseconds.")
@click.option("-r", "--real-time", type=int, help="Limit the amount of real time the program can run for in milliseconds.")
@click.option("-f", "--file-size", type=int, help="Limit the size of files that the program can create / modify in kB.")
@click.option("-p", "--processes", type=int, help="Number of processes (or threads) the program can use.")
@click.option("-i", "--stdin", help="Redirect stdin from file.", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("-o", "--stdout", help="Redirect stdout to file.", type=click.Path(dir_okay=False, writable=True))
@click.option("-e", "--stderr", help="Redirect stderr to file.", type=click.Path(dir_okay=False, writable=True))
@click.option("--stderr-to-stdout", help="Redirect stderr to stdout.", is_flag=True)
@click.option("-s", "--stats", help="File to write stats data to.", type=click.File(mode="w"))
@click.option("-x", "--exitcode", help="Return the same exitcode as child.", is_flag=True)
@click.argument("program")
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def run(stats, exitcode, **kwargs):
    pid = os.fork()
    if pid == 0:  # Child process
        child(**kwargs)
    else:
        run_stats = parent(pid, **kwargs)
        if stats:
            json.dump(asdict(run_stats), stats)
        if exitcode:
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
    max_rss_kilobytes = int(usage.ru_maxrss * 1.024)    # rusage is in KiB

    timeouted = False
    if real_time and duration_ms >= real_time:
        timeouted = True
    if cpu_time and cpu_time_ms >= cpu_time:
        timeouted = True

    return RunStats(exit_code, max_rss_kilobytes, cpu_time_ms, duration_ms, timeouted)


def child(memory, cpu_time, file_size, processes, program, args, stdin, stdout, stderr, stderr_to_stdout, **_):
    if memory:
        memory_bytes = memory * 1000
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

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

    # drop all capabilities
    pyprctl.cap_inheritable.clear()
    pyprctl.cap_ambient.clear()
    pyprctl.cap_permitted.clear()
    pyprctl.set_no_new_privs()

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

    os.execv(program, (os.path.basename(program),) + args)
