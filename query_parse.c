#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pool.h"
#include "pool_config.h"
#include "pool_type.h"
#include "parser/parser.h"

#define MAX 10000

POOL_REQUEST_INFO _req_info;
POOL_REQUEST_INFO *Req_info = &_req_info;
POOL_CONFIG _pool_config;
POOL_CONFIG *pool_config = &_pool_config;
ProcessType processType;

/*
 * Where to send query
 */
typedef enum
{
    POOL_PRIMARY,
    POOL_STANDBY,
    POOL_EITHER,
    POOL_BOTH
}           POOL_DEST;   


int main(int argc, char **argv) {
    bool        error;
	List       *parsetree_list;
	Node       *node;
	RawStmt    *parsetree;
	int			len;

	FILE *fp = NULL;
	char    line[MAX];
	char    query[MAX]; 

	if (argc != 2)
	{
		printf("Error: Please pass a SQL file\n");
		printf("Usage: %s <filename>\n", argv[0]);
		exit(1);
	}

	if((fp=fopen(argv[1],"r")) == NULL)
	{
		printf("Error: couldn not open '%s'\n", argv[1]);
		exit(1);
	}
	
	while (fgets(line, MAX, fp) != NULL)
	{
		strcat(query, line);
	}
	len = strlen(query);
	query[len-1] = '\0'; 

	fclose(fp);

	MemoryContextInit();

	parsetree_list = raw_parser(query, &error);
	node = raw_parser2(parsetree_list); 

	if (parsetree_list == NULL)
		printf("syntax error: %s\n", argv[1]);	

	printf("\n");	
	printf("** READ or WRITE query:\n\n");
	/* READ or WRITE */
	is_read_or_write_query(node, query);

	printf("\n");	
	printf("** Find function names:\n\n");
	/* Find function */
	pool_has_function_call(node);

	printf("\n");	
	printf("** Convert raw parse tree to a query string:\n\n");
	printf("%s\n", nodeToString(node));

	return 0;
}
