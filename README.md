<div align="center">
  <img src=".github/icon.svg" alt="Logo" height="80">
  <p>Parent is a simple wrapper that allows you to run a program with limited resources and access.</p>
</div>


## Available options

### Resource limits

The resources available for the program can be limited using these options. The limits are enforced using the Linux
kernel's rlimit.

| Option               | Description                                                                |
|----------------------|----------------------------------------------------------------------------|
| `-m / --memory N`    | The program's maximum memory address space in kilobytes.                   |
| `-t / --cpu-time N`  | The program's maximum CPU time in milliseconds.                            |
| `-r / --real-time N` | The program's maximum real-time execution time in milliseconds.            |
| `--stack N`          | The program's stack size limit in kilobytes. (-1 for unlimited)            |
| `-f / --file-size N` | The program's maximum file size in kilobytes that it can create or modify. |
| `-p / --processes N` | The number of threads, or processes, the program can use.                  |

### I/O

Program's stdin, stdout, and stderr will by default be redirected to parent's. You can change this behaviour using these
options.

| Option               | Description                              |
|----------------------|------------------------------------------|
| `--stdin FILE`       | Redirect a file to the program's stdin.  |
| `--stdout FILE`      | Redirect the program's stdout to a file. |
| `--stderr FILE`      | Redirect the program's stdout to a file. |
| `--stderr-to-stdout` | Redirect the program's stderr to stdout. |

### File access

The program can access any file on the system by default. You can use these settings to restrict its access. Make sure 
you at least allow access to the program itself, since if you enable any of these options, the default behavior will be 
to prevent access to any files. File access is limited using Linux kernel's landlock. These options can be used multiple
times to allow access to multiple paths.

| Option                | Description                                                                          |
|-----------------------|--------------------------------------------------------------------------------------|
| `--fs-readonly PATH`  | Allow the program read from files or folders located under the provided path.        |
| `--fs-writeonly PATH` | Allow the program write to files of folders located under the provided path.         |
| `--fs-readwrite PATH` | Allow the program read or write to files of folders located under the provided path. |

### Environment

The program inherits environment variables by default. It is possible to disable default inheritance and pass additional
environment variables.

| Option             | Description                  |
|--------------------|------------------------------|
| `--env NAME VALUE` | Set an environment variable. |
| `--empty-env`      | Do not inherit environment.  |

### Syscalls

The program cannot use `kill` syscall by default (to prevent it from sending `SIGSTOP` to parent) while `--seccomp-default` is not set.
You can use these options to allow or deny certain syscalls.

| Option                     | Description                             |
|----------------------------|-----------------------------------------|
| `--seccomp-default POLICY` | Default policy for syscalls.            |
| `--seccomp-allow SYSCALL`  | Allow certain syscalls.                 |
| `--seccomp-deny SYSCALL`   | Deny certain syscalls (return ERRNO 1). |
| `--seccomp-kill SYSCALL`   | Deny certain syscalls (kill process).   |

### Miscelaneous options

| Option                   | Description                              |
|--------------------------|------------------------------------------|
| `--drop-caps`            | Drop the program's capabilities.         |
| `-s / --stats FILE`      | Save execution statistics to a file.     |
