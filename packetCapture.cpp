#include <bits/stdc++.h>
#include <sys/socket.h>
#include <string.h>
//#include <sys/types.h>
#include <stdio.h> 
#include <stdlib.h> //for exit(0);
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


