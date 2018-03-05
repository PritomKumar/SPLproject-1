#include<iostream>
#include<sstream>
#include<stdio.h>
#include <fstream>

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

typedef struct  ethernetHeader{  // total 14 bytes
                                        //[Link Layer]**//
    unsigned char ethDestination[6];    //destination ethernet address
    unsigned char ethSource[6];         //source ethernet address
    unsigned char ethType[2];           //ethernet type

};


typedef struct IPHeader{	///total 20 bytes

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

typedef struct TCPHeader{

    unsigned char sourcePort[2];
    unsigned char destPort[2];
    unsigned char sequenceNumber[4];
    unsigned char acknowledgementNumber[4];
    unsigned char headerLength;
    unsigned char flags;
    unsigned char windowSizeValue[2];
    unsigned char checksum[2];
    unsigned char urgentPoiter[2];

};

typedef struct UDPHeader{

    unsigned char sourcePort[2];
    unsigned char destPort[2];
    unsigned char checksumCovrage[2];
    unsigned char checksum[2];

};

typedef struct ARPHeader{

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

void readAndWriteFullPcapDataAsCharacterAndInteger(FILE *fp ){

    FILE *output;
	unsigned char ch;
	unsigned char str[16];
	int i=0;

    output = fopen("outputFile.txt","w");
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
            for(int j=0;j<16;j++){
				read = str[j] ;
				cout << read  << " ";
            }
            printf(" \n");
            fputs(" \n", output);
            i=0;
        }
	}
}

void printDataPayload(int counter, int len ,FILE *fp , FILE *segment){

	cout <<"------------------DATA Payload--------------------- " << endl <<endl;

	unsigned char ch;
	int j=0;
	fprintf(segment, "\n\n------------------DATA Payload for Packet No : %d  ---------------------\n\n", counter +1);
	while(len--) {
		j++;
		fread(&ch,1,1,fp);
		printf("%.02x " , ch&(0xff));

		//writeDataPayLoadInFile();
		if(isprint(ch)) {
			fputc( ch ,segment);
		}
		else {
			fputs(".", segment);
		}

		if(j%8==0) cout << "   " ;
		if(j%16==0) {
			cout << endl;
			j=0;
		}
	}
}

int readHeadersFromFile(int len,FILE *fp){

	ethernetHeader ethhdr;
	IPHeader iphdr;
	TCPHeader tcphdr;
	UDPHeader udphdr;
	ARPHeader arphdr;

	fread(&ethhdr , sizeof(struct ethernetHeader) , 1 , fp);
	len = len - sizeof(struct ethernetHeader); // subtracting ethernet header size
											   // from length .
	//cout << endl <<(int)ethhdr.ethType[1] <<endl;

	if((int)ethhdr.ethType[1] == 0){    //check the ethernet type .
		fread(&iphdr , sizeof(struct IPHeader) , 1 , fp);
		len = len - sizeof(struct IPHeader);	   // subtracting IP header size
												   // from length .
		//cout << endl <<(int)iphdr.protocol <<endl;

		if( (int)iphdr.protocol == 6 ){
			fread(&tcphdr , sizeof(struct TCPHeader) , 1 , fp);
			len = len - sizeof(struct TCPHeader);  // subtracting TCP header size
												   // from length .
		}
		else if( (int)iphdr.protocol == 17 ){
			fread(&udphdr , sizeof(struct UDPHeader) , 1 , fp);
			len = len - sizeof(struct UDPHeader);  // subtracting UDP header size
												   // from length .
		}

	}
	else if((int)ethhdr.ethType[1] == 6){
		fread(&arphdr , sizeof(struct ARPHeader) , 1 , fp);
		len = len - sizeof(struct ARPHeader);	   // subtracting  ARP header size
												   // from length .
	}

	return len;
}

int main(){

	FILE *fp;
	FILE *output;
	FILE *segment;
	unsigned char ch;
	unsigned char str[16];


	fp = fopen("alice.pcap","rb");
	segment = fopen("PacketDataSegments.txt","w");

	//readAndWriteFullPcapDataAsCharacterAndInteger(fp );

	pcapGlobalHeader globhdr;
	fread(&globhdr, sizeof(struct pcapGlobalHeader), 1, fp);

	int counter=0;

	while(1){

		packetHeader  pachdr;

		fread(&pachdr , sizeof(struct packetHeader) , 1 , fp);
		if(feof(fp)) break;

		int len = dataSize(pachdr) ;

        cout <<"\n\nPacket no : " << counter << " and Packet size : " <<  len <<endl <<endl;
		len = readHeadersFromFile(len , fp );

		printDataPayload(counter ,len , fp , segment);

		counter++;
		//if (counter>1) break;  //control how many packets will be shown.
	}
	cout << "\n\nTotal packets = " << counter <<endl;
	fclose(segment);
	fclose(fp);
}
