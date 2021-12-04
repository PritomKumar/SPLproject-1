struct pcapGlobalHeader { 	//total 24 bytes

        unsigned char magicNumber[4];   		 // magic number , 4 byte
        unsigned char majorVersionNumber[2];   	 // major version number ,2 byte
        unsigned char minorVersionNumber[2];  	 // minor version number , 2 byte
        unsigned char timeOffsetGMT[4];       	 // GMT to local correction , 4 byte
        unsigned char sigfigs[4];        	 	 // accuracy of timestamps , 4 byte
        unsigned char maxSnapshotLenght[4];      // max length of captured packets, in octets , 4 byte
        unsigned char linkLayerProtocol[4];      // data link type , 4 byte
};

struct packetHeader{	//total 16 bytes
		unsigned char timeStamps[4] ;				// timestamps in seconds from 1970
		unsigned char packetCaptureTime[4];			// capture time in microseconds
		unsigned char packetSizeFromData[4];		// saved data size in packets
		unsigned char packetLengthFromWire[4];		// packet length captured from wire

};

struct ethernetHeader{  // total 14 bytes
                                        //[Link Layer]**//
    unsigned char ethDestination[6];    //destination ethernet address
    unsigned char ethSource[6];         //source ethernet address
    unsigned char ethType[2];           //ethernet type

};

struct IPHeader{	//total 20 bytes

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

struct TCPHeader{ // total 20 bytes

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

struct UDPHeader{ // total 8 bytes

    unsigned char sourcePort[2];
    unsigned char destPort[2];
    unsigned char checksumCovrage[2];
    unsigned char checksum[2];

};

struct ARPHeader{ // total 28 bytes

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

struct wholePacket{

	ethernetHeader ethhdr;
	IPHeader iphdr;
	TCPHeader tcphdr;
	UDPHeader udphdr;
	ARPHeader arphdr;
	int dataPayloadSize;
	unsigned char data[20000];

};

wholePacket packet[5000];


