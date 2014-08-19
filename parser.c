#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <byteswap.h>
#include <zlib.h>

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

#define CHUNK 262144
static int inf(FILE *source, FILE *dest);
int UncompressData( const unsigned char* abSrc, int nLenSrc, unsigned char* abDst, int nLenDst );

#pragma pack(1)
struct Pkt_FFXIV
{
	uint8_t unk1[16]; //magic#? Bytes 0-15
	uint64_t timestamp; //unix timestamp, big endian 16-23
	uint32_t size; //Total payload size (including bytes 0-27), big endian, bytes 24-27
	uint8_t unk2[2]; //28-29 
	uint16_t message_count; //Number of messages in payload, big endian, bytes 30-31
	uint8_t flag1; //Unknown, byte 32
	uint8_t flag2; //Compression, byte 33
	uint8_t unk3[6]; //unknown, 34-39
	unsigned char *data; //40+
};
struct Pkt
{
        uint32_t socket;
        uint8_t ip_addr[4];
        uint16_t port; //Little endian
        uint32_t len;
        uint32_t flags;
	struct Pkt_FFXIV *data;	
};
#pragma pack()

int main(int argc, char **argv)
{
	FILE *fp = NULL;
	if(--argc)
		fp = fopen(argv[1],"rb");
	else
		fp = fopen("log.bin","rb");
	if(!fp)
		return 1;

	if(argc > 1)
	{
		fseek(fp,atoi(argv[2]),0);
		printf("Seek to 0x%X, %s\n", ftell(fp), argv[2]);
	}

	struct Pkt packet;

	printf("sizeof(Pkt): 0x%X\n", sizeof(struct Pkt));
	printf("sizeof(Pkt_FFXIV): 0x%X\n", sizeof(struct Pkt_FFXIV));

	while(fread(&packet, sizeof(struct Pkt)-sizeof(char*), 1, fp)) //Read all known data
	{
		getchar();
		if(!packet.len)
			continue;
		packet.data = malloc(sizeof(struct Pkt_FFXIV)); //Allocate enough space based on known length of data per packet
		fread(packet.data, sizeof(struct Pkt_FFXIV)-sizeof(unsigned char*), 1, fp);
		
		size_t to_read = packet.len-(sizeof(struct Pkt_FFXIV)-sizeof(unsigned char*)); //Read the remaining buffer
		packet.data->data = malloc(to_read); //Try to hold the uncompressed size too
		fread(packet.data->data, to_read, 1, fp);

		//Decompress stream
		if(packet.data->flag2)
		{
			unsigned char *t_data = malloc(CHUNK);
			UncompressData(packet.data->data,to_read,t_data,CHUNK);
			free(packet.data->data);
			packet.data->data = t_data;
		}
		printf("sock: %u\n", packet.socket);
		printf("addr: %u.%u.%u.%u\n", packet.ip_addr[0], packet.ip_addr[1], packet.ip_addr[2], packet.ip_addr[3]);
		printf("port: %u\n", packet.port);
		printf("magn: high %llX low %llX\n", packet.data->unk1, packet.data->unk1[8]);
		printf(" len: %u\n", packet.len);
		printf("flag: %u\n", packet.flags);		
		printf("time: %llu\n", packet.data->timestamp);
		printf("size: %u\n", packet.data->size);
		printf("msgc: %u\n", packet.data->message_count);
		printf("flag: %u %u\n", packet.data->flag1, packet.data->flag2);
		if(packet.data->size)
			printf("data: 0x%08X\n", *((unsigned int*)packet.data->data));
		if(packet.data->flag2)
			for(int i = 4; i < 100; i++)
				printf("%02X ", packet.data->data[i]);
		printf("\n------------------\n");

		free(packet.data->data);
		free(packet.data);		
		//TODO: Deflate
		//TODO: Write to SQLite
		printf("tell: 0x%X\n", ftell(fp));
	}
	fclose(fp);
	return 0;
}

int UncompressData( const unsigned char* abSrc, int nLenSrc, unsigned char* abDst, int nLenDst )
{
    z_stream zInfo ={0};
    zInfo.total_in=  zInfo.avail_in=  nLenSrc;
    zInfo.avail_out= nLenDst;
    zInfo.next_in= (unsigned char*)abSrc;
    zInfo.next_out= abDst;

    int nErr, nRet= -1;
    nErr= inflateInit( &zInfo );               // zlib function
    if ( nErr == Z_OK ) {
        nErr= inflate( &zInfo, Z_FINISH );     // zlib function
        if ( nErr == Z_STREAM_END ) {
            nRet= zInfo.total_out;
        }
    }
    inflateEnd( &zInfo );   // zlib function
    return( nRet ); // -1 or len of output
}
