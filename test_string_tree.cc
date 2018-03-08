// Copyright (C) 2018 David Helkowski

#include<stdio.h>
#include"string_tree.h"
#include"parser.h"

int main( int argc, char *argv[] ) {
	string_tree_c string_tree;
	string_tree.store( "test", (void *)31 );
	string_tree.store( "test", (void *)32 );
	//void *got = string_tree.get( "test" );
	
	arrc *arr = string_tree.getarr( "test" );
	
	for( int i=0;i<arr->count;i++ ) {
		printf("data: %p\n", arr->items[ i ] );
	}
	delete arr;
	//printf("data: %i\n",(int)got );
	//printf("done");
	
	parserc parser;
	nodec *root = parser.parse("<xml><val>test</val></xml>");
	//printf("num children in root: %i\n", root->numchildren );
	if( !root ) { printf("No root node\n"); return 1; }
	nodec *xml = root->getnode( "xml" );
	//printf("num children in xml: %i\n", xml->numchildren );
	if( !xml ) { printf("Cannot find xml node\n"); return 1; }
	nodec *val = xml->getnode( "val" );
	if( !val ) { printf("Cannot find val node\n"); return 1; }
	printf("value: %s\n", val->value );
	
	return 0;
}