# Quicknotes
## Debugging

- Before getting started with debugging, the board needs to have a debugger server running.
- The host connects and acts as a client. 
- This service is provided by OpenOCD.

To create and run the server on the board:
```bash
 openocd -s scripts/ -f interface/cmsis-dap.cfg -f target/max78000.cfg -c "bindto 0.0.0.0; init"
```

The server is now running and you should see the green LED blinking rapidly.

- There are multiple ways to connect to a debugger server on the board.
- To make everything portable, eCTF organizers have provided you with a way to connect using a Docker container. 
- However, if you have `gdb-multiarch` installed already, you can connect to the server directly.

### GDB on Docker
```
                                               
   ┌───────┐Port 3333                          
   │ GDB   ├───┐                               
   │ in    │   │                   ┌────────┐  
   │ Cont- │   │              ┌───►│OpenOCD │  
   │ ainer │   │              │    │server  │  
 ┌─└───────┘─┐ ▼              │   ┌└────────┘┐ 
 │  Host     ├────────────────┘ ─ │ Board    │ 
 │  machine  │Port 3333           │          │ 
 └───────────┘                    └──────────┘ 
                                               
```

*Command*
```
docker run --rm -it                                      \
 -p 3333:3333/tcp                                        \
 -v {PATH_TO_DIRECTORY_CONTAINING_TARGET}:/out           \
 --workdir=/root                                         \
 --entrypoint /bin/bash                                  \
 {DECODE_IMAGE_NAME}                                     \
 -c " cp -r /out/* /root/ && gdb-multiarch {TARGET}.elf "
```

Once inside the gdb shell, connect to the OpenOCD server
```
(gdb) target extended-remote {HOST_MACHINE_IP}:3333
```


*Explanation*

1. `docker run --rm -it \`
   - `docker run`: Command to create and start a new container.
   - `--rm`: Automatically remove the container when it exits.
   - `-it`: Run the container in interactive mode with a terminal (otherwise it just runs and exits).

2. `-p 3333:3333/tcp \`
   - `-p xxxx:yyyy/tcp`: Map port `xxxx` of the host to port `yyyy` of the container, allowing TCP traffic.

3. `-v {PATH_TO_DIRECTORY_CONTAINING_TARGET}:/out \`
   - `-v {PATH_TO_DIRECTORY_CONTAINING_TARGET}:/out`: Mount a directory from the host to the container at `/out`, allowing access to files. Here, your target will be the `.elf` file that GDB will use.

4. `--workdir=/root \`
   - `--workdir=/root`: Set the working directory inside the container to `/root`.

5. `--entrypoint /bin/bash \`
   - `--entrypoint /bin/bash`: Override the default entrypoint of the container to use `/bin/bash`, allowing for command execution.

6. `{DECODE_IMAGE_NAME} \`
   - `{DECODE_IMAGE_NAME}`: Specify the name of the Docker image to use for creating the container.

7. `-c " cp -r /out/* /root/ && gdb-multiarch {TARGET}.elf "`
   - `-c`: Pass a command to be executed in the container.
   - `cp -r /out/* /root/`: Copy all files from the mounted directory `/out` to the `/root` directory in the container.
   - `gdb-multiarch {TARGET}.elf`: Run the `gdb-multiarch` debugger on the specified target executable.
   

### GDB on Host
```
                                               
                                   ┌────────┐  
 ┌───────────┐                ┌───►│OpenOCD │  
 │  GDB      │                │    │server  │  
 │  on       │                │   ┌└────────┘┐ 
 │  Host     │────────────────┘ ─ │ Board    │ 
 │  machine  │Port 3333           │          │ 
 └───────────┘                    └──────────┘ 
                                                                             
```

*Command*
```
gdb-multiarch {TARGET.elf}
```

Once inside the gdb shell, connect to the OpenOCD server
```
(gdb) target extended-remote 127.0.0.1:3333
```
	
### Telnet (OpenOCD)

Run:
```
telnet localhost 4444
```

You should now be inside the OpenOCD shell where you can inspect the contents of the board.

# Common Issues
## Bad Flash / Stuck at requesting update

- This occurs when a flash overwrites the ECTF bootloader. 
- It might also happen due to the DAPLink interface (provides serial communications and debugging) is no longer working.

*DAPLink Interface Fix*

1. Get the `DAPLink_NoReset.hex` from [DAPLink - eCTF 2025](https://ectfmitre.gitlab.io/ectf-website/2025/getting_started/daplink.html)
2. Get the board into MAINTENANCE mode by:
	1. Keeping SW5 pressed,
	2. Uplugging the device
	3. Plugging it back in
	4. Releasing SW5
3. Mount the device as storage (should appear automatically in most OSs)
4. Drag and drop the `.hex` file.
5. Let the device auto restart.

*Bootloader Install*

1. Get the insecure bootloader `insecure.bin` from [Bootloader - eCTF 2025](https://ectfmitre.gitlab.io/ectf-website/2025/system/bootloader.html#ectf-bootloader)
2. Mount the device as storage (should appear automatically in most OSs)
3. Drag and drop the `.bin` file.
4. Let the device auto restart.

*Flashing your program*

1. Get the board into update mode by
	1. Keeping SW1 pressed,
	2. Uplugging the device
	3. Plugging it back in
	4. Releasing SW1
2. Running the flash tool as follows
```bash
python -m ectf25.utils.flash ./build_out/{PROGRAM}.bin {DEVICE_PORT}
```

For example:
```bash
python -m ectf25.utils.flash ./build_out/max78000.bin /dev/tty.usbmodem11302

or 

python -m ectf25.utils.flash gdb_challenge.bin /dev/ttyACM0
```