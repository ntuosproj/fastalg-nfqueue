//vim: set sw=4 ts=4 sts=4 et:
#include<inttypes.h>
#include<stdio.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<string.h>
#include<unistd.h>

#define MAX_PATH_LEN 200


/*
 * The original purpose of this function is to dump every byte of a internet packet.
 *
 * This function will create a diretory "falgnfq-dump-dir" under current working directory,
 * and creat a dump file under "falgnfq-dump-dir" each time this function be called.
 *
 * The name of the dump file depends on the first parameter "const char* filename".
 */
int falgnfq_dump_payload(
	const char* filename,  const char* payload, uint16_t len){

	uint16_t dumped = 0;
	char dump_file_path[ strlen(filename) + 30 ];
	char dump_dir_path[] = "falgnfq-dump-dir";
	char buf[50] = {0};
	char buf_offset = 0;
	char current_byte;
	int i = 0, j = 0;

	//create a dir "falgnfq-dump-dir" under current working directory
	struct stat st = {0};
	if(stat(dump_dir_path, &st) == -1){
		mkdir(dump_dir_path, 0700);
	}

	//create a dump file under "falgnfq-dump-dir"
	sprintf(dump_file_path, "%s/%s", dump_dir_path, filename);
	FILE* fp= fopen( dump_file_path, "w" );

	for(dumped = 0; (len - dumped)/4 > 0 ; dumped += 4){
		//4 bytes in a line
		buf_offset = 0;
		for(i = 0; i < 4; i++){
			current_byte = payload[ dumped + i ];
			for(j = 7; j>=0; j--){
				buf[ buf_offset + j ] = ( (current_byte & 0x01) == 1 )? '1': '0';
				current_byte = current_byte >> 1;
			}
			if( i == 3 ){
				buf[ buf_offset + 8 ] = '\n';
				buf[ buf_offset + 9 ] = '\0';
				fputs( buf, fp );
			}else{
				//There is a space between every two bytes in the same line.
				buf[ buf_offset + 8 ] = ' ';
				buf_offset += 9;
			}
		}
	}
	if( len - dumped > 0){
		buf_offset = 0;
		for( ; len - dumped > 0; dumped++ ){
			current_byte = payload[ dumped ];
			for(j=7; j>=0; j--){
				buf[ buf_offset + j ] = ( (current_byte & 0x01) == 1 )? '1': '0';
				current_byte = current_byte >> 1;
			}
			buf[ buf_offset + 8 ] = ' ';
			buf_offset += 9;
		}
		buf[ buf_offset - 1] = '\0';
		fprintf( fp, "%s", buf );
	}

	fclose(fp);
	//return value "dumped" should equals to "len"
	return dumped;
}
