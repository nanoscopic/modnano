// Copyright (C) 2018 David Helkowski

#include "parser.h"
#include<stdio.h>
#ifdef DARWIN
  #include "stdlib.h"
#endif
#ifdef NOSTRING
  void memset(char *s, int c, int n) {
    char *se = s + n;
    while(s < se)	*s++ = c;
	}
#else
  #include <string.h>
#endif

int dh_memcmp(char *a,char *b,int n) {
  int c = 0;
  while( c < n ) {
    if( *a != *b ) return c+1;
    a++; b++; c++;
  }
  return 0;
}

nodec::nodec( struct nodec *newparent ) {
  static int pos = 0;
  int size = sizeof( struct nodec );
  //struct nodec *self = (struct nodec *) malloc( size );
  //memset( (char *) self, 0, size );
  this->parent      = newparent;
  this->pos = ++pos;
  
  this->numchildren = 0;
  this->numvals = 0;
  this->valz = 0;
  
  //return self;
}

nodec::nodec() {
  //int size = sizeof( struct nodec );
  //struct nodec *self = (struct nodec *) malloc( size );
  //memset( (char *) self, 0, size );
  //return self;
}

nodec::~nodec() {
  nodec *curnode;
  attc *curatt;
  nodec *next;
  attc *nexta;
  curnode = this->firstchild;
  while( curnode ) {
    next = curnode->next;
    //del_nodec( curnode );
    delete curnode;
    if( !next ) break;
    curnode = next;
  }
  curatt = this->firstatt;
  while( curatt ) {
    nexta = curatt->next;
    //free( curatt );
    delete curatt;
    curatt = nexta;
  }
  if( valz ) delete valz;
  //free( node );
}

attc::attc( nodec *newparent ) {
  //int size = sizeof( struct attc );
  //struct attc *self = (struct attc *) malloc( size );
  //memset( (char *) self, 0, size );
  //memset( this, 0, sizeof( attc ) );
  this->parent  = newparent;
  //return self;
  next = 0;
  valz = 0;
  value = 0;
}

//#define DEBUG

void escape_att( struct attc *att );

nodec* parserc::parse( char *xmlin ) {
    char  *tagname, *attname, *attval, *val;
    struct nodec *root    = new nodec();
    int    tagname_len    = 0;
    int    attname_len    = 0;
    int    attval_len     = 0;
    struct nodec *curnode = root;
    struct nodec *temp;
    struct attc  *curatt  = NULL;
    char   *cpos          = &xmlin[0];
    int    pos            = 0;
    int    res            = 0;
    int    dent;
    register int let;
    char att_escaped = 0;
    
    #ifdef DEBUG
    printf("Entry to C Parser\n");
    #endif
    
    val_1:
      #ifdef DEBUG
      printf("val_1: %c\n", *cpos);
      #endif
      let = *cpos;
      switch( let ) {
        case 0:   goto done;
        case '<': goto val_x;
      }
      if( !curnode->numvals ) {
        curnode->value = cpos;
        curnode->vallen = 1;
      }
      curnode->numvals++;
      cpos++;
      
    val_x:
      #ifdef DEBUG
      printf("val_x: %c\n", *cpos);
      #endif
      let = *cpos;
      switch( let ) {
        case 0:
          goto done;
        case '<':
          switch( *(cpos+1) ) {
            case '!':
              if( *(cpos+2) == '[' ) { // <![
                //if( !strncmp( cpos+3, "CDATA", 5 ) ) {
                if( *(cpos+3) == 'C' &&
                    *(cpos+4) == 'D' &&
                    *(cpos+5) == 'A' &&
                    *(cpos+6) == 'T' &&
                    *(cpos+7) == 'A'    ) {
                  cpos += 9;
                  curnode->type = 1;
                  goto cdata;
                }
                else {
                  cpos++; cpos++;
                  goto val_x;//actually goto error...
                }
              }
              else if( *(cpos+2) == '-' && // <!--
                *(cpos+3) == '-' ) {
                  cpos += 4;
                  goto comment;
              }
              else {
                cpos++;
                goto bang;
              }
            case '?':
              cpos+=2;
              goto pi;
          }
          tagname_len = 0; // for safety
          cpos++;
          goto name_1;
      }
      if( curnode->numvals == 1 ) curnode->vallen++;
      cpos++;
      goto val_x;
      
    comment_1dash:
      cpos++;
      let = *cpos;
      if( let == '-' ) goto comment_2dash;
      goto comment_x;
      
    comment_2dash:
      cpos++;
      let = *cpos;
      if( let == '>' ) {
        cpos++;
        goto val_1;
      }
      goto comment_x;
      
    comment:
      let = *cpos;
      switch( let ) {
        case 0:   goto done;
        case '-': goto comment_1dash;
      }
      if( !curnode->numcoms ) {
        curnode->comment = cpos;
        curnode->comlen = 1;
      }
      curnode->numcoms++;
      cpos++;
    
    comment_x:
      let = *cpos;
      switch( let ) {
        case 0: goto done;
        case '-': goto comment_1dash;
      }
      if( curnode->numcoms == 1 ) curnode->comlen++;
      cpos++;
      goto comment_x;
      
    pi:
      let = *cpos;
      if( !let ) goto done;
      if( let == '?' && *(cpos+1) == '>' ) {
        cpos += 2;
        goto val_1;
      }
      cpos++;
      goto pi;

    bang:
      let = *cpos;
      if( !let ) goto done;
      if( let == '>' ) {
        cpos++;
        goto val_1;
      }
      cpos++;
      goto bang;
    
    cdata:
      let = *cpos;
      //if( !let ) goto done;
      if( let == ']' && *(cpos+1) == ']' && *(cpos+2) == '>' ) {
        cpos += 3;
        goto val_1;
      }
      if( !curnode->numvals ) {
        curnode->value = cpos;
        curnode->vallen = 0;
        curnode->numvals = 1;
      }
      if( curnode->numvals == 1 ) curnode->vallen++;
      cpos++;
      goto cdata;
      
    name_1:
      #ifdef DEBUG
      printf("name_1: %c\n", *cpos);
      #endif
      let = *cpos;
      if( !let ) goto done;
      switch( let ) {
        case ' ':
        case 0x0d:
        case 0x0a:
          cpos++;
          goto name_1;
        case '/': // regular closing tag
          tagname_len = 0; // needed to reset
          cpos++;
          goto ename_1;
      }
      tagname       = cpos;
      tagname_len   = 1;
      cpos++;
      goto name_x;
      
    name_x:
      #ifdef DEBUG
      printf("name_x: %c\n", *cpos);
      #endif
      let = *cpos;
      switch( let ) {
        case 0:
          goto done;
        case ' ':
        case 0x0d:
        case 0x0a:
          curnode     = curnode->addchildr( tagname, tagname_len );
          attname_len = 0;
          cpos++;
          goto name_gap;
        case '>':
          curnode     = curnode->addchildr( tagname, tagname_len );
          cpos++;
          goto val_1;
        case '/': // self closing
          temp = curnode->addchildr( tagname, tagname_len );
          temp->z = cpos +1 - xmlin;
          tagname_len            = 0;
          cpos+=2;
          goto val_1;
      }
      
      tagname_len++;
      cpos++;
      goto name_x;
          
    name_gap:
      let = *cpos;
      switch( *cpos ) {
        case 0:
          goto done;
        case ' ':
        case 0x0d:
        case 0x0a:
          cpos++;
          goto name_gap;
        case '>':
          cpos++;
          goto val_1;
        case '/': // self closing
          curnode->z = cpos+1-xmlin;
          curnode = curnode->parent;
          if( !curnode ) goto done;
          cpos+=2; // am assuming next char is >
          goto val_1;
        case '=':
          cpos++;
          goto name_gap;//actually goto error
      }
        
    att_name1:
      #ifdef DEBUG
      printf("attname1: %c\n", *cpos);
      #endif
      let = *cpos;
      switch( *cpos ) {
        case 0: goto done;
        case 0x27:
          cpos++;
          attname = cpos;
          attname_len = 0;
          goto att_nameqs;
      }
      attname = cpos;
      attname_len = 1;
      cpos++;
      goto att_name;
      
    att_space:
      let = *cpos;
      switch( let ) {
        case 0: goto done;
        case ' ':
        case 0x0d:
        case 0x0a:
          cpos++;
          goto att_space;
        case '=':
          cpos++;
          goto att_eq1;
      }
      // we have another attribute name, so continue
        
    att_name:
      #ifdef DEBUG
      printf("attname: %c\n", *cpos);
      #endif
      let = *cpos;
      switch( let ) {
        case 0: goto done;
        case '/': // self closing     !! /> is assumed !!
          curatt = curnode->addattr( attname, attname_len );
          attname_len            = 0;
          
          curnode->z = cpos+1-xmlin;
          curnode = curnode->parent;
          if( !curnode ) goto done;
          cpos += 2;
          goto val_1;
        case ' ':
          if( *(cpos+1) == '=' ) {
            cpos++;
            goto att_name;
          }
          curatt = curnode->addattr( attname, attname_len );
          attname_len = 0;
          cpos++;
          goto att_space;
        case '>':
          curatt = curnode->addattr( attname, attname_len );
          attname_len = 0;
          cpos++;
          goto val_1;
        case '=':
          attval_len = 0;
          curatt = curnode->addattr( attname, attname_len );
          attname_len = 0;
          cpos++;
          goto att_eq1;
      }
      
      if( !attname_len ) attname = cpos;
      attname_len++;
      cpos++;
      goto att_name;
      
    att_nameqs:
      #ifdef DEBUG
      printf("nameqs: %c\n", *cpos);
      #endif
      let = *cpos;
      switch( let ) {
        case 0: goto done;
        case 0x27:
          cpos++;
          goto att_nameqsdone;
      }
      attname_len++;
      cpos++;
      goto att_nameqs;
      
    att_nameqsdone:
      #ifdef DEBUG
      printf("nameqsdone: %c\n", *cpos);
      #endif
      let = *cpos;
      switch( let ) {
        case 0: goto done;
        case '=':
          attval_len = 0;
          curatt = curnode->addattr( attname, attname_len );
          attname_len = 0;
          cpos++;
          goto att_eq1;
      }
      goto att_nameqsdone;
      
    att_eq1:
      att_escaped = 0;
      let = *cpos;
      switch( let ) {
        case 0:
          goto done;
        case '/': // self closing
          if( *(cpos+1) == '>' ) {
            curnode->z = cpos+1-xmlin;
            curnode = curnode->parent;
            if( !curnode ) goto done;
            cpos+=2;
            goto att_eq1;
          }
          break;
        case '"':
          cpos++;
          goto att_quot;
        case 0x27: // '
          cpos++;
          goto att_quots;
        case '`':
          cpos++;
          goto att_tick;
        case '>':
          cpos++;
          goto val_1;
        case ' ':
          cpos++;
          goto att_eq1;
        case '\\':
          att_escaped = 1;
          attval_len += 2;
          cpos += 2;
          goto att_eqx;
      }  
      if( !attval_len ) attval = cpos;
      attval_len++;
      cpos++;
      goto att_eqx;
      
    att_eqx:
      let = *cpos;
      switch( let ) {
        case 0:
          goto done;
        case '/': // self closing
          if( *(cpos+1) == '>' ) {
            curnode->z = cpos+1-xmlin;
            curnode = curnode->parent;
            if( !curnode ) goto done;
            curatt->value = attval;
            curatt->vallen = attval_len;
            if( att_escaped ) escape_att( curatt );
            attval_len    = 0;
            cpos += 2;
            goto val_1;
          }
          break;
        case '>':
          curatt->value = attval;
          curatt->vallen = attval_len;
          if( att_escaped ) escape_att( curatt );
          attval_len    = 0;
          cpos++;
          goto val_1;
        case ' ':
          curatt->value = attval;
          curatt->vallen = attval_len;
          if( att_escaped ) escape_att( curatt );
          attval_len    = 0;
          cpos++;
          goto name_gap;
        case '\\':
          att_escaped = 1;
          if( !attval_len ) attval = cpos;
          attval_len += 2;
          cpos += 2;
          goto att_eqx;
      }
      
      if( !attval_len ) attval = cpos;
      attval_len++;
      cpos++;
      goto att_eqx;
      
    att_quot:
      let = *cpos;
      if( !let ) goto done;
      if( let == '"' ) {
        if( attval_len ) {
          curatt->value = attval;
          curatt->vallen = attval_len;
          if( att_escaped ) escape_att( curatt );
          attval_len = 0;
        }
        cpos++;
        goto name_gap;
      }
      if( !attval_len ) attval = cpos;
      if( let == '\\' ) {
        att_escaped = 1;
        
        attval_len += 2;
        cpos += 2;
        goto att_quot;
      }
      
      attval_len++;
      cpos++;
      goto att_quot;
      
    att_quots:
      let = *cpos;
      if( !let ) goto done;
      if( let == 0x27 ) {
        if( attval_len ) {
          curatt->value = attval;
          curatt->vallen = attval_len;
          if( att_escaped ) escape_att( curatt );
          attval_len = 0;
        }
        cpos++;
        goto name_gap;
      }
      if( !attval_len ) attval = cpos;
      if( let == '\\' ) {
        att_escaped = 1;
        attval_len += 2;
        cpos += 2;
        goto att_quots;
      }
      
      attval_len++;
      cpos++;
      goto att_quots;
      
    att_tick:
      let = *cpos;
      if( !let ) goto done;
      if( let == '`' ) {
        if( attval_len ) {
          curatt->value = attval;
          curatt->vallen = attval_len;
          if( att_escaped ) escape_att( curatt );
          attval_len = 0;
        }
        cpos++;
        goto name_gap;
      }
      if( !attval_len ) attval = cpos;
      if( let == '\\' ) {
        att_escaped = 1;
        attval_len += 2;
        cpos += 2;
        goto att_tick;
      }
      
      attval_len++;
      cpos++;
      goto att_tick;
      
    ename_1:
      let = *cpos;
      if( !let ) goto done;
      
      if( let == '>' ) {
        curnode->namelen = tagname_len;
        curnode->z = cpos-xmlin;
        curnode = curnode->parent; // jump up
        if( !curnode ) goto done;
        tagname_len++;
        cpos++;
        root->err = -1;
        goto error;
      }
      tagname       = cpos;
      tagname_len   = 1;
      cpos++;
      // continue
      
    ename_x: // ending name
      let = *cpos;
      if( !let ) goto done;
      if( let == '>' ) {
        //curnode->namelen = tagname_len;
        
        if( curnode->namelen != tagname_len ) {
          goto error;
        }
        if( res = dh_memcmp( curnode->name, tagname, tagname_len ) ) {
          cpos -= tagname_len;
          cpos += res - 1;
          goto error;
        }
        curnode->z = cpos-xmlin;
        curnode = curnode->parent; // jump up
        if( !curnode ) goto done;
        tagname_len++;
        cpos++;
        
        goto val_1;
      }
      tagname_len++;
      cpos++;
      goto ename_x;
    error:
      root->err = - ( int ) ( cpos - &xmlin[0] );
      this->pcurnode = root;
      //root->err = 1;
      return root;
    done:
      #ifdef DEBUG
      printf("done\n", *cpos);
      #endif
      this->pcurnode = root;
      this->pcurnode->curchild = this->pcurnode->firstchild;
      #ifdef DEBUG
      printf("returning\n", *cpos);
      #endif
      return root;
}

void escape_att( struct attc *att ) {
    int offset = 0;
    for( int i=0;i<att->vallen;i++ ) {
        char let = att->value[i];
        if( let == '\\' ) {
            att->value[i-offset] = att->value[i+1];
            offset++;
            i++;
            continue;
        }
        att->value[i-offset] = let;
    }
    att->vallen -= offset;
    att->value[ att->vallen ] = 0x00;
}

nodec *nodec::addchildr( char *newname, int newnamelen ) {//, char *newval, int newvallen, int newtype ) {
	nodec *newnode = new nodec( this );
  newnode->name    = newname;
  newnode->namelen = newnamelen;
  node_tree.store( newname, newnamelen, (void *) newnode );
  //newnode->value   = newval;
  //newnode->vallen  = newvallen;
  //newnode->type    = newtype;
  if( this->numchildren == 0 ) {
    this->firstchild = newnode;
    //this->lastchild  = newnode;
    this->numchildren++;
    return newnode;
  }
  else {
    //this->lastchild->next = newnode;
    //this->lastchild = newnode;
    this->numchildren++;
    return newnode;
  }
}

attc *nodec::addattr( char *newname, int newnamelen ) {//, char *newval, int newvallen ) {
  attc *newatt = new attc( this );
  newatt->name    = newname;
  newatt->namelen = newnamelen;
  //newatt->value   = newval;
  //newatt->vallen  = newvallen;
  att_tree.store( newname, newnamelen, (void *) newatt );
  if( !this->numatt ) {
    this->firstatt = newatt;
    //this->lastatt  = newatt;
    this->numatt++;
    return newatt;
  }
  else {
    //this->lastatt->next = newatt;
    //this->lastatt = newatt;
    this->numatt++;
    return newatt;
  }
}

nodec *nodec::getnode( char *name ) {
	return (nodec *) node_tree.get( name );
}
void *nodec::getmore( char *name ) {
	return more_tree.get( name );
}
void nodec::addmore( char *newname, void *val ) {
	more_tree.store( newname, val );
}
void nodec::setmore( char *newname, void *val ) {
	more_tree.delkey( newname );
	more_tree.store( newname, val );
}

arrc *nodec::getnodes( const char *name ) {
	return node_tree.getarr( name );
}
attc *nodec::getatt( char *name ) {
	return (attc *) att_tree.get( name );
}
char *nodec::getval() {
	if( valz ) return valz;
	valz = new char[ vallen + 1 ];
	valz[ vallen ] = 0;
	strncpy( valz, value, vallen );
	return valz;
}
char *attc::getval() {
	if( valz ) return valz;
	valz = new char[ vallen + 1 ];
	valz[ vallen ] = 0;
	strncpy( valz, value, vallen );
	return valz;
}
char *nodec::getval( char *name ) {
	nodec *sub = getnode( name );
	if( !sub ) { return 0; }
	return sub->getval();
}

char *nodec::getattval( char *name ) {
	attc *sub = getatt( name );
	if( !sub ) { return 0; }
	return sub->getval();
}

void nodec::setval( char *newval ) {
	if( valz ) {
		delete valz;
		valz = 0;
	}
	value = newval;
	vallen = strlen( newval );
}

attc::~attc() {
	if( valz ) delete valz;
}

void nodec::dump() {
	printf("\n");
	printf("Nodes:\n");
	node_tree.dump();
	printf("Atts:\n");
	att_tree.dump();
	printf("\n");
}
