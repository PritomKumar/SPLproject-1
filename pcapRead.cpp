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

typedef struct  ethernetHeader{  // total 14 bytes
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

ethernetHeader ethhdr[10000000];
IPHeader iphdr[10000000];
TCPHeader tcphdr[10000000];
UDPHeader udphdr[10000000];
ARPHeader arphdr[10000000];

int totalPackets;
unsigned char data[10000][10000];
int dataPayloadSize[1000000];

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

void initializeTestArray(int *tarray ,int len){

    for(int i=0  ; i < len ; i++){
        tarray[i] = -1;
    }
}

void printfDataArray(int counter){
	unsigned char ch;
	for (int i =0 ; i< counter ; i++){
		cout <<"\n\nPacket no : " << i << " and Data Payload size : " <<  dataPayloadSize[i] <<endl <<endl;
		for(int j =0 ; j< dataPayloadSize[i] ; j++){
			ch = data[i][j];
			printf("%.02x " , ch&(0xff));
		}
    }
}

int IPHeaderSourceData(IPHeader iphdr){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<3 ; i++){
		cc = iphdr.sourceIpAddr[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int IPHeaderDestinationData(IPHeader iphdr){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<3 ; i++){
		cc = iphdr.destIpAddr[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int dataSizeForIPHeader(IPHeader iphdr){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = iphdr.ipLength[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int dataSizeForTCPHeader(TCPHeader tcphdr){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = tcphdr.sourcePort[i];
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

		data[counter][ct] = ch;

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

	fread(&ethhdr[counter] , sizeof(struct ethernetHeader) , 1 , fp);  // Reading etherNet Header
	len = len - sizeof(struct ethernetHeader); // subtracting ethernet header size
											   // from length .
	//cout << endl <<(int)ethhdr.ethType[1] <<endl;

	if((int)ethhdr[counter].ethType[1] == 0){    //check the ethernet type . 0 means IPV4 and 6 means ARP
		fread(&iphdr[counter] , sizeof(struct IPHeader) , 1 , fp);
		len = len - sizeof(struct IPHeader);	   // subtracting IP header size
												   // from length .
		//cout << endl <<(int)iphdr.protocol <<endl;

		if( (int)iphdr[counter].protocol == 6 ){	// Check protocol ; 6 means TCP , 17 Means UDP
			fread(&tcphdr[counter] , sizeof(struct TCPHeader) , 1 , fp);
			len = len - sizeof(struct TCPHeader);  // subtracting TCP header size
												   // from length .
		}
		else if( (int)iphdr[counter].protocol == 17 ){
			fread(&udphdr[counter] , sizeof(struct UDPHeader) , 1 , fp);
			len = len - sizeof(struct UDPHeader);  // subtracting UDP header size
												   // from length .
		}

	}
	else if((int)ethhdr[counter].ethType[1] == 6){			//check the ethernet type . 0 means IPV4 and 6 means ARP
		fread(&arphdr[counter] , sizeof(struct ARPHeader) , 1 , fp);
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
			dataPayloadSize[counter] = len;

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

        int len = dataSizeForIPHeader( iphdr[i] );
       // cout <<"\n\nPacket no : " << i << " and Packet size : " <<  len <<endl <<endl;
       // cout <<"\n\nPacket no : " << i << " and Packet payload : " <<  dataPayloadSize[i] <<endl <<endl;

    }
	//printfDataArray(counter);

	FILE *dataSegment;
	dataSegment = fopen("dataFile.txt" , "w");
	/*
    for(int i=0 ; i< totalPackets ; i++){
        cout <<"\n\nPacket no : " << i+1 << " and Source IP : " ;
        for(int j =0 ; j< 4 ; j++){
            cout << (int)iphdr[i].sourceIpAddr[j]  << "." ;
        }
        cout << endl <<endl;
    }
	*/

	int *tarray;
    tarray = new int[totalPackets];

    initializeTestArray(tarray , totalPackets);
	int ct2=0;

    for(int k=0 ; k< totalPackets ; k++){
        int ct =0 ;

        for(int l = 0 ; l < totalPackets ; l++){
            if(IPHeaderSourceData(iphdr[k]) != tarray[l]){
                ct++;
            }
        }
        if(ct == totalPackets){
            tarray[ct2] = IPHeaderSourceData(iphdr[k]);
            ct2++;
        }
    }

    IPHeader *tempIPHdr;
    tempIPHdr = new IPHeader[totalPackets];


    int ct = 0;

    for(int i=0 ; i< ct2 ; i++){

        for(int j=0 ; j< totalPackets ; j++){
            if(tarray[i]== IPHeaderSourceData(iphdr[j])){
                tempIPHdr[ct] = iphdr[j];
                ct++;
            }
        }
    }

    for(int i=0 ; i< totalPackets ; i++){
         iphdr[i]=tempIPHdr[i];
    }

    delete [] tempIPHdr;

	for(int i=0 ; i< totalPackets ; i++ ){
		cout << tarray[i] << " ";
	}
	cout << "\n\n";
	/*
	int sum1 = 0;
	int sum2 = 0;
	for(int x=0 ; x< ct2 ; x++){
		if(tarray[x] == -1) break;
		int ct3=0;

		for(int x2=0 ; x2 < totalPackets ; x2++){
			if(tarray[x]== IPHeaderSourceData(iphdr[x2]))
				ct3++;
		}
		cout << ct3 << " " ;


		sum2 = sum2 + ct3;
		int *tarray2;
		tarray2 = new int[ct3];

		initializeTestArray(tarray2 , ct3);
		int ct2=0;

		for(int k= sum1 ; k< sum2 ; k++){
			int ct =sum1  ;

			for(int l = 0 ; l < sum2-sum1 ; l++){
				if(IPHeaderDestinationData(iphdr[k]) != tarray2[l]){
					ct++;
				}
			}
			if(ct == sum2){
				tarray2[ct2] = IPHeaderDestinationData(iphdr[k]);
				ct2++;
			}
		}

		for(int i=0 ; i< ct2 ; i++ ){
			cout << tarray2[i] << " ";
		}
		cout << "\n\n";

		IPHeader *tempIPHdr;
		tempIPHdr = new IPHeader[totalPackets];


		int ct = 0;

		for(int i=0 ; i< ct2 ; i++){

			for(int j=sum1 ; j< sum2 ; j++){
				if(tarray2[i]== IPHeaderDestinationData(iphdr[j])){
					tempIPHdr[ct] = iphdr[j];
					ct++;
				}
			}
		}

		for(int i=sum1 ; i< sum2; i++){
			 iphdr[i]=tempIPHdr[i];
		}
		delete [] tempIPHdr;

		sum1 = sum1 +ct3;

	}
*/
    for(int k = 0 ; k< totalPackets ; k++){
        //cout <<"\n\nPacket no : " << k+1 << " and Source port : " <<  IPHeaderSourceData(iphdr[k]) << " and Destination port : " <<  IPHeaderDestinationData(iphdr[k]) << endl <<endl;
        //cout <<"\n\nPacket no : " << k+1 << " and Destination port : " <<  IPHeaderDestinationData(iphdr[k]) <<endl <<endl;
        //cout <<"\n\nPacket no : " << k+1 << " and Source port : " <<  IPHeaderSourceData(iphdr[k]) <<endl <<endl;
        //cout <<"\n\nPacket no : " << k+1 << " and Source port : " <<  tarray[k] <<endl <<endl;
    }

	for(int i=0 ; i< totalPackets ; i++){
		if((int)ethhdr[i].ethType[1] == 0){  //checking if its IP Header
			if( (int)iphdr[i].protocol == 6 ) {   //checking if its TCP Header
				if(dataPayloadSize[i] != 0){   // checks if data payload is empty or not
					fprintf(dataSegment, "\n\n----------DATA Payload for Packet No : %d  PayloadSize = %d  -----------\n\n", i+1 , dataPayloadSize[i]);
					//cout <<"\n\nPacket no : " << i+1 << " and Data Payload size : " <<  dataPayloadSize[i] <<endl <<endl;
					//cout <<"\n\nPacket no : " << i+1 << " and Source port : " <<  dataSizeForTCPHeader(tcphdr[i]) <<endl <<endl;
					//cout <<"\n\nPacket no : " << i+1 << " and Time to leave : " <<  (int)iphdr[i].TTL <<endl <<endl;

					for(int j =0 ; j< dataPayloadSize[i] ; j++){
						ch = data[i][j];
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
    //cout << "\n\nTotal packets = " << totalPackets <<endl;
	fclose(dataSegment);

}
