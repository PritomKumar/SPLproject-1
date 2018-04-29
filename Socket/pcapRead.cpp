#include<iostream>
#include<stdio.h>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h> //for exit(0);
//#include <sys/types.h>
//#include <errno.h> //For errno - the error number
//#include <linux/types.h> 
//#include <netinet/tcp.h>   //Provides declarations for tcp header
//#include <netinet/ip.h> 
//#include <netinet/udp.h> 
//#include <netinet/if_ether.h>
//#include <netinet/in.h>

using namespace std;

#define ETH_P_ALL   0x0003 

#if BYTE_ORDER == BIG_ENDIAN
#define htons(n)
#else 
#define htons(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#endif ///converting host byte order..

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
				//fprintf(output , "%d " , read );
            }
            printf(" \n");
            //fputs(" \n", output);
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

unsigned long int IPHeaderSourceData(unsigned char *sourceIpAddr){

	unsigned char cc;
    unsigned long int x = 0;

	for(int i=0 ; i<3 ; i++){
		cc = sourceIpAddr[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

unsigned long int IPHeaderDestinationData(unsigned char *destIpAddr){

	unsigned char cc;
    unsigned long int x = 0;

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
    unsigned long int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = destPort[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

unsigned long int sequenceNumber(unsigned char *sequenceNumber){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<4 ; i++){
		cc = sequenceNumber[i];
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

void sortPacketsAccordingToSequenceNumber(){

	 for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){
			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) ==  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				if(IPHeaderDestinationData(packet[j].iphdr.destIpAddr) == IPHeaderDestinationData(packet[j+1].iphdr.destIpAddr) ){
					if(sourcePortFromTcpHeader(packet[j].tcphdr.sourcePort) ==  sourcePortFromTcpHeader(packet[j+1].tcphdr.sourcePort)){
						if(destPortFromTcpHeader(packet[j].tcphdr.destPort) ==  destPortFromTcpHeader(packet[j+1].tcphdr.destPort)){
							if(sequenceNumber(packet[j].tcphdr.sequenceNumber) >  sequenceNumber(packet[j+1].tcphdr.sequenceNumber)){
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



void addPacketHeaderInFile(int data_size , FILE *packetCapture){
    
    unsigned long int epochTime = 1520144305;
    unsigned long int captureTime = 479050000;
    unsigned long int packetSize = data_size;
    unsigned long int packetLength = data_size;    
    
    fwrite(&epochTime,4,1,packetCapture);
    fwrite(&captureTime,4,1,packetCapture);
    fwrite(&packetSize,4,1,packetCapture);
    fwrite(&packetLength,4,1,packetCapture);
}


void addPcapGlobalHeaderInFile(FILE *packetCapture){
   
    unsigned long int magicNumber = 2712847316; 
    unsigned short int majorVersion = 2;
    unsigned short int minorVersion = 4;
    unsigned long int timeZone = 0;
    unsigned long int sigfigs = 0;
    unsigned long int lengthOfCapturePackets = 65535;
    unsigned long int linkLayerHedrType = 1;
        
    fwrite(&magicNumber,4,1,packetCapture);
    fwrite(&majorVersion,2,1,packetCapture);
    fwrite(&minorVersion,2,1,packetCapture);
    fwrite(&timezone,4,1,packetCapture);
    fwrite(&sigfigs,4,1,packetCapture);
    fwrite(&lengthOfCapturePackets,4,1,packetCapture);
    fwrite(&linkLayerHedrType,4,1,packetCapture);
        
}

void checkIPVersion(unsigned char *bufferArray){
	
	 if(bufferArray[13] == 0) {
       
       		printf("IPV4\n");
       }    
       
       else if(bufferArray[13] == 6) {
       
       		printf("ARP\n");
       }    
       
       else {
       		printf("Others\n");
       }

}

bool checkIPVersionAndProtocol(unsigned char *bufferArray){

	if(*(bufferArray+13) == 0){
	
		if(*(bufferArray+23) == 6){
		
			return true;
		}
	}
	else return false;
}

int hexadecimalToInteger(unsigned char *array){

	unsigned char cc;
    unsigned long int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = array[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

void printReleventInformation(unsigned char *bufferArray){

	printf("\n\nPrinting Relevent Information ----------------------- \n\n");
		   		
    printf("Source IP Address : %d.%d.%d.%d\n",(int)bufferArray[26] , (int)bufferArray[27] , (int)bufferArray[28] , (int)bufferArray[29]  );
	printf("Destination IP Address : %d.%d.%d.%d\n",(int)bufferArray[30] , (int)bufferArray[31] , (int)bufferArray[32] , (int)bufferArray[33]  );
		   
	unsigned long int sourcePort = 0;	    
	for(int i = 34 ; i < 36 ; i++){
		sourcePort = sourcePort<<8;
		sourcePort = sourcePort | bufferArray[i];
	}		
	printf("Source Port : %ld\n" , sourcePort);
			
    unsigned long int destinationPort = 0;    
    for(int i = 36 ; i < 38 ; i++){
		destinationPort = destinationPort<<8;
		destinationPort = destinationPort | bufferArray[i];
	}
	printf("Destination Port : %ld\n" , destinationPort);

}

void packetCapture(){

	FILE *packetCapture;
	int sockRaw;
	
	sockRaw=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	//sockRaw=socket(AF_INET,SOCK_STREAM, 0 );
	if(sockRaw<0){
	
		printf("Error in creating socket\n");
		exit(0);
	}
	printf("Enter a name for pcap file to save TCP data . \n");

	char pcapName[100];	
	scanf("%s", pcapName);
	strcat (pcapName , ".pcap");
	
	packetCapture=fopen( pcapName ,"wb");
	addPcapGlobalHeaderInFile(packetCapture);

	unsigned char bufferArray[10000];
	
	int counter = 0;
	printf("Enter the number of Packets You want to capture :  \n");
	cin >> counter ;
	
	struct sockaddr saddr;
	int saddrLength = sizeof (saddr);
	int dataSize;
	
	 
	 for(int i=0;i<counter; ){
	
		dataSize=recvfrom(sockRaw,bufferArray,65536,0, &saddr , (socklen_t *)&saddrLength);
		
		
		if(dataSize<0){
			printf("Error in reading recvfrom function\n");
			exit(0);
		}	
		
		//if(checkIPVersionAndProtocol(bufferArray)){
		if( bufferArray[13] == 0 && bufferArray[23] == 6){ // Checking if its tcp Packet	
			i++;
			printf("\n\nSocket reading for Packet %d ----- Packet size =  %d\n" ,i ,dataSize );

			for(int j=0;j<dataSize;j++){
		         if (j%16 == 0)
				   printf("\n");
				 
				else if (j%16 == 8)
				  printf(" -- ");
				else
				  printf(" ");
		        printf("%.02X ", bufferArray[j]);
		    }
		   // printf("\nProtocol Type == %d\n\n" , bufferArray[23]);
		    
		    printReleventInformation(bufferArray);
		   //	printf("\n\nProtocol Type : ");
		   	//checkIPVersion(bufferArray);
			//fwrite(&bufferArray,sizeof(unsigned char )*dataSize,1,packetCapture);
		
			addPacketHeaderInFile(dataSize , packetCapture);

			fwrite(&bufferArray,sizeof(unsigned char )*dataSize,1,packetCapture);	

		}
	}
	
	printf("\n\n");

}


int main(){

	FILE *fp;

	unsigned char ch;
	unsigned char str[16];
	int choice =0;

	fp = fopen("a.pcap","rb");
	/*
	cout << "What do you want to do ?" <<endl;
	cout << "Choice 1 : Read the full Pcap File in Character and Integers and Print them on the Screen and in text file ." <<endl;
	cout << "Choice 2 : Read the Individual Packets in PCAP file and Print them as Hexadecimal on the Screen and character in text file . "<<endl;
	cout << "\t   Additionally read and count the packet numbers . " <<endl;
	*/
	cout << "Enter your choice :  " ;

	cin >> choice;

	int counter=0;
	
	if(choice == 3 ) packetCapture();

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

	sortPacketsAccordingToSequenceNumber();

    for(int k = 0 ; k< totalPackets ; k++){
        cout <<"\nPacket no : " << k+1 << " and Source IP Address : " <<  (int)packet[k].iphdr.sourceIpAddr[0]  << "."  << (int)packet[k].iphdr.sourceIpAddr[1] << "."
        << (int)packet[k].iphdr.sourceIpAddr[2] << "." <<  (int)packet[k].iphdr.sourceIpAddr[3]<< " and Destination IP Address : " << (int)packet[k].iphdr.destIpAddr[0] << "."
		<< (int)packet[k].iphdr.destIpAddr[1] << "." << (int)packet[k].iphdr.destIpAddr[2] << "." << (int)packet[k].iphdr.destIpAddr[3] <<endl;
        //cout <<"\n\nPacket no : " << k+1 << " and Destination port : " <<  IPHeaderDestinationData(iphdr[k]) <<endl <<endl;
        cout <<"\nPacket no : " << k+1 << " and Source port : " <<  sourcePortFromTcpHeader(packet[k].tcphdr.sourcePort)
        << " and Destination port : " <<  destPortFromTcpHeader(packet[k].tcphdr.destPort) <<endl;
        cout <<"\nPacket no : " << k+1 << " and Sequence Number : " <<  sequenceNumber(packet[k].tcphdr.sequenceNumber) <<endl ;
        //cout <<"\n\nPacket no : " << k+1 << " and Source port : " <<  sourceIPAdressDataArray[k] <<endl <<endl;
    }

	fprintf(dataSegment , "\n\n-----------Collected Full Data File : %d -----\n\n" , 1);

	int ct=1;
	for(int i=0 ; i< totalPackets ; i++){
		unsigned long int sqNumber = sequenceNumber(packet[i].tcphdr.sequenceNumber);
		if((int)packet[i].ethhdr.ethType[1] == 0){  //checking if its IP Header
			if( (int)packet[i].iphdr.protocol == 6 ) {   //checking if its TCP Header
				if(packet[i].dataPayloadSize != 0){   // checks if data payload is empty or not
					if(sqNumber + packet[i].dataPayloadSize == sequenceNumber(packet[i+1].tcphdr.sequenceNumber)){ // check if the next sequence is valid
						//fprintf(dataSegment, "\n\n----------DATA Payload for Packet No : %d  PayloadSize = %d  -----------\n\n", i+1 , packet[i].dataPayloadSize );
						//cout <<"\n\nPacket no : " << i+1 << " and Data Payload size : " <<  dataPayloadSize[i] <<endl <<endl;
						//cout <<"\n\nPacket no : " << i+1 << " and Source port : " <<  dataSizeForTCPHeader(tcphdr[i]) <<endl <<endl;
						//cout <<"\n\nPacket no : " << i+1 << " and Time to leave : " <<  (int)iphdr[i].TTL <<endl <<endl;

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
					if(i==totalPackets-1) break; //total
					if(IPHeaderSourceData(packet[i].iphdr.sourceIpAddr) !=  IPHeaderSourceData(packet[i+1].iphdr.sourceIpAddr)
						|| IPHeaderDestinationData(packet[i].iphdr.destIpAddr) != IPHeaderDestinationData(packet[i+1].iphdr.destIpAddr)
						|| sourcePortFromTcpHeader(packet[i].tcphdr.sourcePort) !=  sourcePortFromTcpHeader(packet[i+1].tcphdr.sourcePort)
						|| destPortFromTcpHeader(packet[i].tcphdr.destPort) !=  destPortFromTcpHeader(packet[i+1].tcphdr.destPort)){

						ct++;
						fprintf(dataSegment , "\n\n-----------Collected Full Data File : %d -----\n\n" , ct);
					}
				}
			}
		}
	}
    //cout << "\n\nTotal packets = " << totalPackets <<endl;
	fclose(dataSegment);

}
