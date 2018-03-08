// Copyright (C) 2018 David Helkowski

#include "string_tree.h"
#include<string.h>

uint32_t fnv1a( const char *str ) {
	uint32_t hval = 0;
    unsigned char *s = (unsigned char *) str;

    while (*s) {
    	hval ^= (uint32_t)*s++;
		hval *= ((uint32_t)0x01000193);
		//hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
	}
	//printf("Hash '%s' to %u\n", str, hval );
    return hval;
}

uint32_t fnv1a( const char *str, int strlen ) {
	uint32_t hval = 0;
    unsigned char *s = (unsigned char *) str;

    for( int i=0;i<strlen;i++ ) {
    //while (*s) {
    	hval ^= (uint32_t)*s++;
		hval *= ((uint32_t)0x01000193);
		//hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
	}
	//printf("Hash '%.*s' to %u\n", strlen, str, hval );
    return hval;
}

void string_tree_c::delkey( char *key ) {
	uint32_t hash = fnv1a( key );
	rb_red_blk_node* rbnode = RBExactQuery( tree, &hash );
	if( rbnode ) RBDelete( tree, rbnode );
}

string_tree_c::string_tree_c() {
	tree=RBTreeCreate(IntComp,IntDest,InfoDest,IntPrint,InfoPrint);
}

string_tree_c::~string_tree_c() {
	RBTreeDestroy(tree);
}

void *string_tree_c::get( char *key, char *multiple ) {
	//printf("Getting %s\n", key );
	snodec *node = rawget( key );
	if( !node ) {
		//printf("Could not find node %s\n", key );
		return 0;
	}
	return node->data;
}

arrc *string_tree_c::getarr( const char *key ) {
	snodec *node = rawget( key );
	if( !node ) return 0;
	arrc *arr = new arrc();
	arr->count = 1;
	arr->items[ 0 ] = node->data;
	node = node->next;
	
	while( node ) {
		if( node->strlen ) {
			int keylen = strlen( key );
			if( keylen == node->strlen && !strncmp( node->str, key, node->strlen ) )
				arr->items[ arr->count++ ] = node->data;
		}
		else {
			if( !strcmp( node->str, key ) )
			arr->items[ arr->count++ ] = node->data;
		}
		node = node->next;
	}
	
	return arr;
}

/*
snodec *string_tree_c::rawget( char *key, uint32_t hash ) {
	snodec *node = (snodec *) RBExactQuery( tree, &hash );
	while( node ) {
		if( !strcmp( node->str, key ) ) return node;
		node = node->next;
	}
	return 0;
}*/

snodec *string_tree_c::rawget( const char *key ) {
	//printf("Attempting to get node %s\n", key );
	uint32_t hash = fnv1a( key );
	rb_red_blk_node* rbnode = RBExactQuery( tree, &hash );
	if( !rbnode ) { return 0; }
	//printf("Found rbnode\n");
	snodec *node = (snodec *) rbnode->info;
	//printf("got %i\n", (int) node );
	int keylen = strlen( key );
	while( node ) {
		if( node->strlen ) {
			//printf("checking %.*s\n", node->strlen, node->str );
			if( keylen == node->strlen && !strncmp( node->str, key, node->strlen ) ) return node;
		}
		else {
			//printf("checking %s\n", node->str );
			if( !strcmp( node->str, key ) ) return node;
		}
		node = node->next;
	}
	
	//printf("ret\n");
	return 0;
}

snodec *string_tree_c::rawget( const char *key, int keylen ) {
	//printf("Attempting to get node %s\n", key );
	uint32_t hash = fnv1a( key, keylen );
	rb_red_blk_node* rbnode = RBExactQuery( tree, &hash );
	if( !rbnode ) { return 0; }
	//printf("Found rbnode\n");
	snodec *node = (snodec *) rbnode->info;
	//printf("got %i\n", (int) node );
	while( node ) {
		if( node->strlen ) {
			if( keylen == node->strlen && !strncmp( node->str, key, node->strlen ) ) return node;
		}
		else {
			int nslen = strlen( node->str );
			if( nslen == keylen && !strncmp( node->str, key, keylen ) ) return node;
		}
		node = node->next;
	}
	
	//printf("ret\n");
	return 0;
}

void string_tree_c::rawput( char *key, int keylen, snodec *orig, snodec *newnode ) {
	uint32_t hash = fnv1a( key, keylen );
	rb_red_blk_node* rbnode = RBExactQuery( tree, &hash );
	if( !rbnode ) { return; } // this function should only be used to replace
	if( rbnode->info == orig ) {
		rbnode->info = newnode;
		return;
	}
	snodec *node = (snodec *) rbnode->info;
	while( node ) {
		if( node->next == orig ) {
			node->next = newnode;
			return;
		}
		node = node->next;
	}
}

void string_tree_c::store( char *key, void *node ) {
	uint32_t hash = fnv1a( key );
	snodec *curnode = rawget( key );
	//printf("Storing %s\n", key );
	if( curnode ) {
		while( curnode->next ) curnode = curnode->next;
		
		snodec *newnode = new snodec( key, node );
		curnode->next = newnode;
	}
	else {
		//printf("No curnode\n");
		curnode = new snodec( key, node );
		//printf("New node ptr: %i\n", (int) curnode );
		uint32_t *hdup = new uint32_t;
		*hdup = hash;
		RBTreeInsert( tree, hdup, curnode );
	}
}


void string_tree_c::store( char *key, int keylen, void *node ) {
	uint32_t hash = fnv1a( key, keylen );
	snodec *curnode = rawget( key, keylen );
	if( curnode ) {
		snodec *next = curnode->next;
		while( curnode->next ) curnode = curnode->next;
		
		snodec *newnode = new snodec( key, keylen, node );
		curnode->next = newnode;
	}
	else {
		curnode = new snodec( key, keylen, node );
		uint32_t *hdup = new uint32_t;
		*hdup = hash;
		RBTreeInsert( tree, hdup, curnode );
	}
}

void IntDest(void* a) {
	//printf("k");
	free((uint32_t*)a);
}
int IntComp(const void* a,const void* b) {
	//printf("compare %u to %u\n", *(uint32_t*)a, *(uint32_t*)b);
  if( *(uint32_t*)a > *(uint32_t*)b) return(1);
  if( *(uint32_t*)a < *(uint32_t*)b) return(-1);
  return(0);
}
void IntPrint(const void* a) { printf("%li",*(uint32_t*)a); }
void InfoPrint(void* a) {
	snodec *node = (snodec *)a;
	printf("%.*s",node->strlen,node->str);
}
void InfoDest(void *a){
	//printf("t");
	snodec *n = (snodec *) a;
	//printf("destroy %s\n", n->str );
}

snodec::snodec( char *newstr, void *newdata, snodec *newnext ) {
	next = newnext;
	str = newstr;
	data = newdata;
	strlen = 0;
	//printf("New snodec - next=%i str=%s data=%i\n", (int)next, str, (int)data );
}

snodec::snodec( char *newstr, int nstrlen, void *newdata, snodec *newnext ) {
	next = newnext;
	str = newstr;
	strlen = nstrlen;
	data = newdata;
	//printf("New snodec - next=%i str=%s data=%i\n", (int)next, str, (int)data );
}

void string_tree_c::dump() {
	RBTreePrint( tree );
}