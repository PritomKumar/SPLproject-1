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
                                        //**[Link Layer]**//
    unsigned char ethDest[6];           //destination ethernet address
    unsigned char ethSrc[6];            //source ethernet address
    unsigned char ethType[2];           //ethernet type

};


typedef struct IPHeader{
                                        //**[Network Layer]**//
    unsigned char headerL;              //Header lenght
    unsigned char Explicit;             //type of service
    unsigned char ipLength[2];          //total length
    unsigned char identification[2];    //Identofication
    unsigned char fragment[2];          //fragment
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
    unsigned char checksum[2];output = fopen("outputFile.txt","w");
    unsigned char urgentPoiter[2];

};

typedef struct UDPHeader{

    unsigned char sourcePort[2];
    unsigned char destPort[2];
    unsigned char checksumCovrage[2];
    unsigned char checksum[2];

};

typedef struct ARP{

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

void readFullPcapDataAsCharacterAndInteger(){

	FILE *input;
	FILE *output;
	unsigned char ch;
	unsigned char str[16];
	int i=0;

	input = fopen("samplePcap.pcap","rb");
	output = fopen("outputFile.txt","w");

	while(!feof(input)){

		fread(&ch,1,1,input);
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

int main(){

	FILE *fp;
	FILE *output;
	unsigned char ch;
	unsigned char str[16];

	//readFullPcapDataAsCharacterAndInteger();

	fp = fopen("samplePcap.pcap","rb");
	output = fopen("outputFile.txt","w");

	pcapGlobalHeader globhdr;

	fread(&globhdr, sizeof(struct pcapGlobalHeader), 1, fp);

    /*int t = dataSize(pachdr);

    cout << t <<endl;
*/
	for(int i =0 ; i<4 ; i++){

		//cout << (int)globhdr.magicNumber[i] << " " ; //hahahahhahaha I am a genius;
		//cout << (char)globhdr.magicNumber[i] << " " ; //hahahahhahaha I am a genius;
		//printf("%.02x " , globhdr.magicNumber[i]&(0xff));
	}

	for(int i =0 ; i<4 ; i++){
		//unsigned int l = (int)pachdr.timeStamps[i];
		//cout << l << " " ; //hahahahhahaha I am a genius;
		//cout << (char)pachdr.timeStamps[i] << " " ; //hahahahhahaha I am a genius;
		//printf("%.02x " , pachdr.timeStamps[i]&(0xff));
	}

	int i=0;

	while(1){

		packetHeader  pachdr;
		fread(&pachdr , sizeof(struct packetHeader) , 1 , fp);
        if(feof(fp)) break;

		//cout << "\n\n timeStamps : " << (int)pachdr.timeStamps[0] <<endl;
		if((int)pachdr.timeStamps[0] == 0) break;

		i++;
		int t = dataSize(pachdr);

        cout <<"\n\nPacket no : " << i << " and Packet size : " <<  t <<endl <<endl;
		int j=0;
		while(t--) {
			j++;
			fread(&ch,1,1,fp);

			printf("%.02x " , ch&(0xff));
			if(j%8==0) cout << "   " ;
			if(j%16==0) {
				cout << endl;
				j=0;
			}

		}

	}
	cout << "\n\nTotal packets = " << i <<endl;

}
