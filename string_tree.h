// Copyright (C) 2018 David Helkowski

#ifndef __STRING_TREE_H
#define __STRING_TREE_H
#include "red_black_tree.h"
#include<stdint.h>

uint32_t fnv1a( const char *str );
uint32_t fnv1a( const char *str, int strlen );

class snodec {
public:
	char *str;
	int strlen;
	void *data;
	snodec *next;
	snodec( char *newstr, void *newdata, snodec *newnext = NULL );
	snodec( char *newstr, int strlen, void *newdata, snodec *newnext = NULL );
};

class arrc {
public:
	int count;
	void *items[30];
};

class string_tree_c {
	rb_red_blk_tree *tree;
	snodec *rawget( const char *key );
	snodec *rawget( const char *key, int keylen );
	void rawput( char *key, int keylen, snodec *orig, snodec *newnode );
	//nodec *rawget( char *key, uint32_t key );         
public:
	string_tree_c();
	~string_tree_c();
	void *get( char *key, char *multiple=NULL );
	void delkey( char *key );
	arrc *getarr( const char *key );
	void store( char *key, void *node );
	void store( char *key, int keylen, void *node );
	void dump();
};

void IntDest(void *); int IntComp(const void *,const void *);
void IntPrint(const void* a); void InfoPrint(void *); void InfoDest(void *);
#endif
