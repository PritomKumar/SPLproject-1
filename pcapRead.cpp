#include<iostream>
#include<stdio.h>

using namespace std;

typedef struct pcapGlobalHeader { 	//total 24 bytes

        unsigned char magicNumber[4];   		 // magic number , 4 byte
        unsigned char majorVersionNumber[2];   	 // major version number ,2 byte
        unsigned char minorVersionNumber[2];  	 // minor version number , 2 byte
        unsigned char timeOffsetGMT[4];       	 // GMT to local correction , 4 byte
        unsigned char sigfigs[4];        	 	 // accuracy of timestamps , 4 byte
        unsigned char maxSnapshotLenght[4];      // max length of captured packets, in octets , 4 byte
        unsigned char linkLayerProtocol[4];      // data link type , 4 byte
};

typedef struct packetHeader{	//total 16 bytes
		unsigned char timeStamps[4] ;				// timestamps in seconds from 1970
		unsigned char packetCaptureTime[4];			// capture time in microseconds
		unsigned char packetSizeFromData[4];		// saved data size in packets
		unsigned char packetLengthFromWire[4];		// packet length captured from wire

};

typedef struct ethernetHeader{  // total 14 bytes
                                        //[Link Layer]**//
    unsigned char ethDestination[6];    //destination ethernet address
    unsigned char ethSource[6];         //source ethernet address
    unsigned char ethType[2];           //ethernet type

};

typedef struct IPHeader{	//total 20 bytes

                                        //[Network Layer]**//
    unsigned char headerL;              //Header lenght
    unsigned char Explicit;             //type of service
    unsigned char ipLength[2];          //total length
    unsigned char identification[2];    //Identofication
    unsigned char fragmentOffset[2];    //fragment
    unsigned char TTL;                  //Time to live
    unsigned char protocol;             //transport layer protocol
    unsigned char headerChecksum[2];    //header checksum
    unsigned char sourceIpAddr[4];      //source ip address
    unsigned char destIpAddr[4];        //destination ip address

};

typedef struct TCPHeader{ // total 20 bytes

    unsigned char sourcePort[2];
    unsigned char destPort[2];
    unsigned char sequenceNumber[4];
    unsigned char acknowledgementNumber[4];
    unsigned char tcpSegmentLenght;
    unsigned char flags;
    unsigned char windowSizeValue[2];
    unsigned char checksum[2];
    unsigned char urgentPoiter[2];

};

typedef struct UDPHeader{ // total 8 bytes

    unsigned char sourcePort[2];
    unsigned char destPort[2];
    unsigned char checksumCovrage[2];
    unsigned char checksum[2];

};

typedef struct ARPHeader{ // total 28 bytes

    unsigned char hardwareType[2];
    unsigned char protocol[2];
    unsigned char hardwareSize;
    unsigned char protocolSize;
    unsigned char opcodeRequest[2];
    unsigned char senderMac[6];
    unsigned char senderIP[4];
    unsigned char targetMac[6];
    unsigned char targetIP[4];

};

typedef struct wholePacket{

	ethernetHeader ethhdr;
	IPHeader iphdr;
	TCPHeader tcphdr;
	UDPHeader udphdr;
	ARPHeader arphdr;
	int dataPayloadSize;
	unsigned char data[10000];

};

wholePacket packet[10000];

int totalPackets;

void readAndWriteFullPcapDataAsCharacterAndInteger(FILE *fp ){

    FILE *output;
	unsigned char ch;
	unsigned char str[16];
	int i=0;

    output = fopen("outputFile.txt","w");
	cout << "All information on PCAP file . First in hexadecimal , next in character and lastly in integer" << endl<<endl;
	fprintf(output , "All Information in PCAP file is as follows ------ \n\n");
	fprintf(output , "   Character    \t\t Integer \n\n");

	while(!feof(fp)){

		fread(&ch,1,1,fp);
		str[i] = ch;
		i++;
		printf("%.02x " , ch&(0xff));


		int read ;
		if(i%8==0) cout << "   " ;
		if(i%16==0){
            for(int j=0;j<16;j++){
                if(isprint(str[j])) {
					cout << str[j] ; //sees if character is printable
					fputc( str[j] ,output);
                }
                else {
					cout << ".";
					fputs(".", output);
				}

            }
			cout << "   " ;
			fputs("   " , output);
            for(int j=0;j<16;j++){
				read = str[j] ;
				cout << read  << " ";
				fprintf(output , "%d " , read );
            }
            printf(" \n");
            fputs(" \n", output);
            i=0;
        }
	}

	fclose(output);
}

int dataSizeForIPHeader(unsigned char *ipLength){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = ipLength[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int dataSize(packetHeader pachdr){
	unsigned char cc;
    int x = 0;

	for(int i=3 ; i>=0 ; i--){
		cc = pachdr.packetSizeFromData[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

void initializeTestArray(int *sourceIPAdressDataArray ,int len){

    for(int i=0  ; i < len ; i++){
        sourceIPAdressDataArray[i] = -1;
    }
}

void printfDataArray(int counter){
	unsigned char ch;
	for (int i =0 ; i< counter ; i++){
		cout <<"\n\nPacket no : " << i+1 << " and Data Payload size : " <<  packet[i].dataPayloadSize <<endl <<endl;
		for(int j =0 ; j< packet[i].dataPayloadSize ; j++){
			ch = packet[i].data[j];
			printf("%.02x " , ch&(0xff));
		}
    }
}

int IPHeaderSourceData(unsigned char *sourceIpAddr){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<3 ; i++){
		cc = sourceIpAddr[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int IPHeaderDestinationData(unsigned char *destIpAddr){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<3 ; i++){
		cc = destIpAddr[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int sourcePortFromTcpHeader(unsigned char *sourcePort){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = sourcePort[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int destPortFromTcpHeader(unsigned char *destPort){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = destPort[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

void sortPacketsAccordingToSourceIPAddress(){

	for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){

			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) >  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				wholePacket temp = packet[j];
				packet[j] = packet[j+1] ;
				packet[j+1] = temp;
			}
		}
    }

}

void sortPacketsAccordingToDestinationIPAddress(){

	for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){
			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) ==  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				if(IPHeaderDestinationData(packet[j].iphdr.destIpAddr) >  IPHeaderDestinationData(packet[j+1].iphdr.destIpAddr) ){
					wholePacket temp = packet[j];
					packet[j] = packet[j+1] ;
					packet[j+1] = temp;
				}
			}
		}
    }

}

void sortPacketsAccordingToSourcePort(){

	for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){
			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) ==  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				if(IPHeaderDestinationData(packet[j].iphdr.destIpAddr) == IPHeaderDestinationData(packet[j+1].iphdr.destIpAddr) ){
					if(sourcePortFromTcpHeader(packet[j].tcphdr.sourcePort) >  sourcePortFromTcpHeader(packet[j+1].tcphdr.sourcePort)){
						wholePacket temp = packet[j];
						packet[j] = packet[j+1] ;
						packet[j+1] = temp;
					}
				}
			}
		}
    }

}

void sortPacketsAccordingToDestinationPort(){

	 for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){
			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) ==  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				if(IPHeaderDestinationData(packet[j].iphdr.destIpAddr) == IPHeaderDestinationData(packet[j+1].iphdr.destIpAddr) ){
					if(sourcePortFromTcpHeader(packet[j].tcphdr.sourcePort) ==  sourcePortFromTcpHeader(packet[j+1].tcphdr.sourcePort)){
						if(destPortFromTcpHeader(packet[j].tcphdr.destPort) >  destPortFromTcpHeader(packet[j+1].tcphdr.destPort)){
							wholePacket temp = packet[j];
							packet[j] = packet[j+1] ;
							packet[j+1] = temp;
						}
					}
				}
			}
		}
    }

}

void printAllDataPayload(int counter, int len ,FILE *fp , FILE *segment){

	unsigned char ch;
	int ct = 0 ;
	int j=0;
	fprintf(segment, "\n\n------------------DATA Payload for Packet No : %d  ---------------------\n\n", counter +1);

	while(len--) {
		j++;
		fread(&ch,1,1,fp);
	//	printf("%.02x " , ch&(0xff));

		//writeDataPayLoadInFile();

		packet[counter].data[ct] = ch;

		if(isprint(ch)) {
			fputc( ch ,segment);
		}
		else {
			fputs(".", segment);
		}

		//if(j%8==0) cout << "   " ;
		if(j%16==0) {
			//cout << endl;
			j=0;
		}
		ct++;
	}
}

int readHeadersFromFile(int len,FILE *fp , int counter ){

	fread(&packet[counter].ethhdr , sizeof(struct ethernetHeader) , 1 , fp);  // Reading etherNet Header
	//packet[counter].ethhdr = tempEthHdr;

	len = len - sizeof(struct ethernetHeader); // subtracting ethernet header size
											   // from length .
	//cout << endl <<(int)ethhdr.ethType[1] <<endl;

	if((int)packet[counter].ethhdr.ethType[1] == 0){    //check the ethernet type . 0 means IPV4 and 6 means ARP
		fread(&packet[counter].iphdr , sizeof(struct IPHeader) , 1 , fp);
		len = len - sizeof(struct IPHeader);	   // subtracting IP header size
												   // from length .
		//cout << endl <<(int)iphdr.protocol <<endl;

		if( (int)packet[counter].iphdr.protocol == 6 ){	// Check protocol ; 6 means TCP , 17 Means UDP
			fread(&packet[counter].tcphdr , sizeof(struct TCPHeader) , 1 , fp);
			len = len - sizeof(struct TCPHeader);  // subtracting TCP header size
												   // from length .
		}
		else if( (int)packet[counter].iphdr.protocol == 17 ){
			fread(&packet[counter].udphdr , sizeof(struct UDPHeader) , 1 , fp);
			len = len - sizeof(struct UDPHeader);  // subtracting UDP header size
												   // from length .
		}

	}
	else if((int)packet[counter].ethhdr.ethType[1] == 6){			//check the ethernet type . 0 means IPV4 and 6 means ARP
		fread(&packet[counter].arphdr , sizeof(struct ARPHeader) , 1 , fp);
		len = len - sizeof(struct ARPHeader);	   // subtracting  ARP header size
												   // from length .
	}

	return len;
}

int main(){

	FILE *fp;

	unsigned char ch;
	unsigned char str[16];
	int choice =0;

	fp = fopen("alice.pcap","rb");
	/*
	cout << "What do you want to do ?" <<endl;
	cout << "Choice 1 : Read the full Pcap File in Character and Integers and Print them on the Screen and in text file ." <<endl;
	cout << "Choice 2 : Read the Individual Packets in PCAP file and Print them as Hexadecimal on the Screen and character in text file . "<<endl;
	cout << "\t   Additionally read and count the packet numbers . " <<endl;
	*/
	cout << "Enter your choice :  " ;

	cin >> choice;

	int counter=0;

	if(choice == 1) readAndWriteFullPcapDataAsCharacterAndInteger( fp );

	else if (choice == 2) {

		FILE *segment;
		segment = fopen("PacketDataSegments.txt","w");

		pcapGlobalHeader globhdr;
		fread(&globhdr, sizeof(struct pcapGlobalHeader), 1, fp);


		cout <<"----------DATA Payload For Individual Packets----------- " << endl <<endl;
		fprintf(segment , "----------DATA Payload For Individual Packets-----------\n\n ");

		while(1){

			packetHeader  pachdr;

			fread(&pachdr , sizeof(struct packetHeader) , 1 , fp);
			if(feof(fp)) break;

			int len = dataSize(pachdr) ;

			//cout <<"\n\nPacket no : " << counter << " and Packet size : " <<  len <<endl <<endl;
			len = readHeadersFromFile(len , fp , counter);
			packet[counter].dataPayloadSize = len;

			//cout <<"\n\nPacket no : " << counter << " and Data Payload size : " <<  dataPayloadSize[counter] <<endl <<endl;

			printAllDataPayload(counter ,len , fp , segment);

			counter++;
			//if (counter>1) break;  //control how many packets will be shown or read.
		}

		totalPackets = counter;
		cout << "\n\nTotal packets = " << totalPackets <<endl;
		fclose(segment);

    }

	fclose(fp);

    for(int i=0 ; i < totalPackets ; i++){

        int len = dataSizeForIPHeader( packet[i].iphdr.ipLength );
       	//cout <<"\n\nPacket no : " << i+1 << " and Packet size : " <<  len <<endl <<endl;
        //cout <<"\n\nPacket no : " << i+1 << " and Packet payload : " <<  packet[i].dataPayloadSize <<endl <<endl;

    }

	//printfDataArray(counter);

	FILE *dataSegment;
	dataSegment = fopen("dataFile.txt" , "w");
/*
    for(int i=0 ; i< totalPackets ; i++){
        cout <<"\n\nPacket no : " << i+1 << " and Source IP : " ;
        for(int j =0 ; j< 4 ; j++){
            cout << (int)packet[i].iphdr.sourceIpAddr[j]  << "." ;
        }
        cout << endl <<endl;
    }

*/
	sortPacketsAccordingToSourceIPAddress();

	sortPacketsAccordingToDestinationIPAddress();

	sortPacketsAccordingToSourcePort();

	sortPacketsAccordingToDestinationPort();


    for(int k = 0 ; k< totalPackets ; k++){
        cout <<"\nPacket no : " << k+1 << " and Source IP Address : " <<  (int)packet[k].iphdr.sourceIpAddr[0]  << "."  << (int)packet[k].iphdr.sourceIpAddr[1] << "."
        << (int)packet[k].iphdr.sourceIpAddr[2] << "." <<  (int)packet[k].iphdr.sourceIpAddr[3]<< " and Destination IP Address : " << (int)packet[k].iphdr.destIpAddr[0] << "."
		<< (int)packet[k].iphdr.destIpAddr[1] << "." << (int)packet[k].iphdr.destIpAddr[2] << "." << (int)packet[k].iphdr.destIpAddr[3] <<endl;
        //cout <<"\n\nPacket no : " << k+1 << " and Destination port : " <<  IPHeaderDestinationData(iphdr[k]) <<endl <<endl;
        cout <<"\nPacket no : " << k+1 << " and Source port : " <<  sourcePortFromTcpHeader(packet[k].tcphdr.sourcePort)
        << " and Destination port : " <<  destPortFromTcpHeader(packet[k].tcphdr.destPort) <<endl;
        //cout <<"\n\nPacket no : " << k+1 << " and Source port : " <<  sourceIPAdressDataArray[k] <<endl <<endl;
    }

	fprintf(dataSegment , "\n\n-----------Collected Full Data File : %d -----\n\n" , 1);

	int ct=1;
	for(int i=0 ; i< totalPackets ; i++){
		if((int)packet[i].ethhdr.ethType[1] == 0){  //checking if its IP Header
			if( (int)packet[i].iphdr.protocol == 6 ) {   //checking if its TCP Header
				if(packet[i].dataPayloadSize != 0){   // checks if data payload is empty or not
					//fprintf(dataSegment, "\n\n----------DATA Payload for Packet No : %d  PayloadSize = %d  -----------\n\n", i+1 , packet[i].dataPayloadSize );
					//cout <<"\n\nPacket no : " << i+1 << " and Data Payload size : " <<  dataPayloadSize[i] <<endl <<endl;
					//cout <<"\n\nPacket no : " << i+1 << " and Source port : " <<  dataSizeForTCPHeader(tcphdr[i]) <<endl <<endl;
					//cout <<"\n\nPacket no : " << i+1 << " and Time to leave : " <<  (int)iphdr[i].TTL <<endl <<endl;

					if(IPHeaderSourceData(packet[i].iphdr.sourceIpAddr) !=  IPHeaderSourceData(packet[i+1].iphdr.sourceIpAddr)
						|| IPHeaderDestinationData(packet[i].iphdr.destIpAddr) != IPHeaderDestinationData(packet[i+1].iphdr.destIpAddr)
						|| sourcePortFromTcpHeader(packet[i].tcphdr.sourcePort) !=  sourcePortFromTcpHeader(packet[i+1].tcphdr.sourcePort)
						|| destPortFromTcpHeader(packet[i].tcphdr.destPort) !=  destPortFromTcpHeader(packet[i+1].tcphdr.destPort)){

						ct++;
						fprintf(dataSegment , "\n\n-----------Collected Full Data File : %d -----\n\n" , ct);
					}

					if(IPHeaderSourceData(packet[i].iphdr.sourceIpAddr) ==  IPHeaderSourceData(packet[i+1].iphdr.sourceIpAddr) ){
						if(IPHeaderDestinationData(packet[i].iphdr.destIpAddr) == IPHeaderDestinationData(packet[i+1].iphdr.destIpAddr) ){
							if(sourcePortFromTcpHeader(packet[i].tcphdr.sourcePort) ==  sourcePortFromTcpHeader(packet[i+1].tcphdr.sourcePort)){
								if(destPortFromTcpHeader(packet[i].tcphdr.destPort) ==  destPortFromTcpHeader(packet[i+1].tcphdr.destPort)){

									for(int j =0 ; j< packet[i].dataPayloadSize ; j++){

										ch = packet[i].data[j];
										//printf("%.02x " , ch&(0xff));
										if(isprint(ch)) {
											fputc( ch ,dataSegment);
										}
										else {
											if(ch == '\n' ) fputs("\n", dataSegment);
											else fputs(".", dataSegment);
										}
									}
								}

							}
						}
					}

				}
			}
		}
	}
    //cout << "\n\nTotal packets = " << totalPackets <<endl;
	fclose(dataSegment);

}
