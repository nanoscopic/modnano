// Copyright (C) 2018 David Helkowski

#ifndef __PARSER_H
#define __PARSER_H
#include"string_tree.h"

#ifdef WIN32
#include<stdlib.h>
#endif

#ifndef NULL
  #define NULL 0x00
#endif

class attc;

class nodec {
public:
	string_tree_c att_tree;
	string_tree_c node_tree;
	string_tree_c more_tree;
  nodec *curchild;
  nodec *parent;
  nodec *next;
  nodec *firstchild;
  //nodec *lastchild;
  attc  *firstatt;
  //attc  *lastatt;
  int   numchildren;
  int   numatt;
  char  *name;
  int   namelen;
  char  *value;
  char  *comment;
  char *valz;
  int   vallen;
  int   comlen;
  int   type;// cdata or normal
  int   numvals;
  int   numcoms;
  int   pos;
  int   err;
  int   z;
  nodec( nodec *newparent );
  nodec();
  ~nodec();
  nodec *addchildr( char *newname, int newnamelen );//, char *newval, int newvallen, int newtype );
  //nodec *nodec_addchild( nodec *self, char *newname, int newnamelen );
  attc *addattr( char *newname, int newnamelen );//, char *newval, int newvallen );
  //attc *nodec_addatt  ( nodec *self, char *newname, int newnamelen );
  nodec *getnode( char *name );
  void addmore( char *newname, void *val );
  void setmore( char *newname, void *val );
  void *getmore( char *name );
  arrc *getnodes( const char *name );
  attc *getatt( char *name );
  char *getval();
  char *getval( char *name );
  char *getattval( char *name );
  void setval( char *newval );
  void dump();
};

class attc {
public:
  nodec *parent;
  attc  *next;
  char  *name;
  int   namelen;
  char  *value;
  char *valz;
  int   vallen;
  attc( nodec *newparent );
  ~attc();
  char *getval();
};

class parserc {
public:
  nodec *pcurnode;
  attc  *curatt;
  nodec* parse( char *newbuf );
};

#endif
