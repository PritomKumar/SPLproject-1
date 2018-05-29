# SPLproject-1
Here is the user manual.
#To run the program do the following from terminal:

    1. Go to root mode
        -> $ sudo su 
        -> Then enter your password
    2. Then change the directory where the program files are stored.
        -> $ cd Directory/../../    
    3. Run the object file 
        -> $ ./textBandit
        [In some computers it may show "bash: ./pcapStat: Permission denied". Use $ chmod 775 ./pcapStat command to resolve]
    4. Then several options will come
        ->Options:
            (1). Capture Raw data Packets using Socket .(Only capture TCP Packets)
		    (2). Analyze a existing PCAP File 
		
                ->> Selecting option '1' will ask you for a file name to make a valid .pcap file where the captured packets will be stored. And it also
                    ask for the number of packets you want to capture . Then capturing will start. When capturing basic packet information such as Source IP Address , Destination IP Address , Source Port Number , Destination Port Number will be shown.
		    After capturing you can open pcap file with other tool like "Wireshark" and "TShark".
                    
                ->> Selecting option '2' will ask you for giving a existing file name to analyze the file.
                    [Must be a .pcap file]
                
                ->> If you choose option  '2' it will give you another list of options. 
                        Options are:
                            (1) Separate the different connections from the Pcap file and write  it in text file.
                            (2) Read and write the full Pcap File in Hexadecimal , Character and Integers and Print it on the Screen and in text file .
                            (3) Write the data payloads from all the packets in file.
			    	Additionally read and count the packet numbers .
                         
        -> After executing a process it will ask the user to repeat the process or not .
	-> Any invalid option given by the user will terminate the whole process.
                  
            
# Program Features:
    
    1. It will make a valid .pcap file following the headers of .pcap file, so the .pcap file can be analyzed by other network monitoring tool
       like 'WireShark', 'TShark' and so on.  
									
    2. It can give the whole conversation between client and server and create text file for HTTP connection. 
    3. It can be used as a security check for network connection .  


# Code properties:
    
    1. It contains 11 source files.

       1. Header File:
            Header.h: It contains all the packet headers, protocol headers.

       2. C++ File:
            main.cpp            : It contains the main function where the program starts from.
            packetCapture.cpp   : It does the process of capturing packets and saving packets in a certain file.
            packetAnalyze.cpp   : It contains all the important functions and saves the analyzed data in file. 
         
       3.Executable File:
            textBandit

# Dependencies:
    1. Linux OS (Because sys/socket.h doesn't work on windows.)
    2. C++ compilers (mainly g++) as it was developed in C++ programming language
    3. Internet connection or Lan connection.
