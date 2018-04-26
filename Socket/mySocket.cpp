#include <bits/stdc++.h>
#include <sys/socket.h>
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


void addPacketHeaderInFile(int data_size , FILE *iFile){
    
    unsigned long int epochTime = 1520144305;
    unsigned long int captureTime = 479050000;
    unsigned long int packetSize = data_size;
    unsigned long int packetLength = data_size;    
    
    fwrite(&epochTime,4,1,iFile);
    fwrite(&captureTime,4,1,iFile);
    fwrite(&packetSize,4,1,iFile);
    fwrite(&packetLength,4,1,iFile);
}


void addPcapGlobalHeaderInFile(FILE *iFile){
   
    unsigned long int magicNumber = 2712847316; 
    unsigned short int majorVersion = 2;
    unsigned short int minorVersion = 4;
    unsigned long int timeZone = 0;
    unsigned long int sigfigs = 0;
    unsigned long int lengthOfCapturePackets = 65535;
    unsigned long int linkLayerHedrType = 1;
        
    fwrite(&magicNumber,4,1,iFile);
    fwrite(&majorVersion,2,1,iFile);
    fwrite(&minorVersion,2,1,iFile);
    fwrite(&timezone,4,1,iFile);
    fwrite(&sigfigs,4,1,iFile);
    fwrite(&lengthOfCapturePackets,4,1,iFile);
    fwrite(&linkLayerHedrType,4,1,iFile);
        
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

void packetCapture(){

	FILE *iFile;
	int sockRaw;
	
	sockRaw=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	//sockRaw=socket(AF_INET,SOCK_STREAM, 0 );
	if(sockRaw<0)
	{
		printf("Error in creating socket\n");
		exit(0);
	}

	iFile=fopen("a.pcap","wb");
	addPcapGlobalHeaderInFile(iFile);

	unsigned char bufferArray[100000];
	
	int counter = 0;
	printf("Enter the number of Packets You want to capture . \n");
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
			printf("\n\nSocket reading for Packet %d ----- packet size %d\n" ,i ,dataSize );

			for(int j=0;j<dataSize;j++){
		         if (j%16 == 0)
				   printf("\n");
				 
				else if (j%16 == 8)
				  printf(" -- ");
				else
				  printf(" ");
		        printf("%.02X ", bufferArray[j]);
		    }
		    
		   
		   printf("\n\nProtocol Type == %d\n\n" , bufferArray[23]);
		   //	printf("\n\nProtocol Type : ");
		   
		   	//checkIPVersion(bufferArray);
		
						 
			//fwrite(&bufferArray,sizeof(unsigned char )*dataSize,1,iFile);
		
			addPacketHeaderInFile(dataSize , iFile);

			fwrite(&bufferArray,sizeof(unsigned char )*dataSize,1,iFile);	

		}
	}
	
	printf("\n\n");


}

int main(){

	packetCapture();

	
}

