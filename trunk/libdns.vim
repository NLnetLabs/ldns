" Vim syntax file
" Language:     C libdns
" Maintainer:   miekg
" Last change:  2004-12-15

" util.h
syn keyword  ldnsMacro MALLOC
syn keyword  ldnsMacro XMALLOC
syn keyword  ldnsMacro REALLOC
syn keyword  ldnsMacro XREALLOC
syn keyword  ldnsMacro FREE
syn keyword  ldnsMacro DEP  

" ldns/rdata.h
syn keyword  ldnsType           ldns_rdf
syn keyword  ldnsType           ldns_rdf_type
syn keyword  ldnsType           ldns_hdr
syn keyword  ldnsType           ldns_status
syn keyword  ldnsType           ldns_rrset
syn keyword  ldnsType           ldns_dname
syn keyword  ldnsConstant       true
syn keyword  ldnsConstant       false
syn keyword  ldnsFunction	ldns_rdf_get_type

syn keyword  ldnsConstant	LDNS_RDF_TYPE_NONE
syn keyword  ldnsConstant	LDNS_RDF_TYPE_DNAME
syn keyword  ldnsConstant	LDNS_RDF_TYPE_INT8
syn keyword  ldnsConstant	LDNS_RDF_TYPE_INT16
syn keyword  ldnsConstant	LDNS_RDF_TYPE_INT32
syn keyword  ldnsConstant	LDNS_RDF_TYPE_A
syn keyword  ldnsConstant	LDNS_RDF_TYPE_AAAA
syn keyword  ldnsConstant	LDNS_RDF_TYPE_STR
syn keyword  ldnsConstant	LDNS_RDF_TYPE_APL
syn keyword  ldnsConstant	LDNS_RDF_TYPE_B64
syn keyword  ldnsConstant	LDNS_RDF_TYPE_HEX
syn keyword  ldnsConstant	LDNS_RDF_TYPE_NSEC
syn keyword  ldnsConstant	LDNS_RDF_TYPE_TYPE
syn keyword  ldnsConstant	LDNS_RDF_TYPE_CLASS
syn keyword  ldnsConstant	LDNS_RDF_TYPE_CERT
syn keyword  ldnsConstant	LDNS_RDF_TYPE_ALG
syn keyword  ldnsConstant 	LDNS_RDF_TYPE_UNKNOWN
syn keyword  ldnsConstant	LDNS_RDF_TYPE_TIME
syn keyword  ldnsConstant	LDNS_RDF_TYPE_PERIOD
syn keyword  ldnsConstant	LDNS_RDF_TYPE_TSIGTIME
syn keyword  ldnsConstant	LDNS_RDF_TYPE_SERVICE
syn keyword  ldnsConstant	LDNS_RDF_TYPE_LOC
syn keyword  ldnsConstant	LDNS_RDF_TYPE_WKS
syn keyword  ldnsConstant	LDNS_RDF_TYPE_NSAP
syn keyword  ldnsConstant	MAX_RDFLEN

" ldns/dns.h
syn keyword  ldnsConstant	LDNS_PORT

" ldns/packet.h
syn keyword  ldnsType           ldns_pkt
syn keyword  ldnsType           ldns_pkt_section
syn keyword  ldnsType		ldns_pkt_type
syn keyword  ldnsConstant	LDNS_QR
syn keyword  ldnsConstant	LDNS_AA
syn keyword  ldnsConstant	LDNS_TC
syn keyword  ldnsConstant	LDNS_CD
syn keyword  ldnsConstant	LDNS_RA
syn keyword  ldnsConstant	LDNS_AD
syn keyword  ldnsConstant	LDNS_PACKET_QUESTION
syn keyword  ldnsConstant	LDNS_PACKET_REFERRAL
syn keyword  ldnsConstant	LDNS_PACKET_ANSWER
syn keyword  ldnsConstant	LDNS_PACKET_NXDOMAIN
syn keyword  ldnsConstant	LDNS_PACKET_NODATA
syn keyword  ldnsConstant	LDNS_SECTION_QUESTION
syn keyword  ldnsConstant	LDNS_SECTION_ANSWER
syn keyword  ldnsConstant	LDNS_SECTION_AUTHORITY
syn keyword  ldnsConstant	LDNS_SECTION_ADDITIONAL
syn keyword  ldnsConstant	LDNS_SECTION_ANY
syn keyword  ldnsConstant	MAX_PACKETLEN


" dns/error.h
syn keyword ldnsMacro	LDNS_STATUS_OK
syn keyword ldnsMacro	LDNS_STATUS_EMPTY_LABEL
syn keyword ldnsMacro	LDNS_STATUS_LABEL_OVERFLOW
syn keyword ldnsMacro	LDNS_STATUS_LABEL_UNDERFLOW
syn keyword ldnsMacro	LDNS_STATUS_DOMAINNAME_OVERFLOW
syn keyword ldnsMacro	LDNS_STATUS_DDD_OVERFLOW
syn keyword ldnsMacro	LDNS_STATUS_PACKET_OVERFLOW
syn keyword ldnsMacro	LDNS_STATUS_INVALID_POINTER
syn keyword ldnsMacro	LDNS_STATUS_MEM_ERR
syn keyword ldnsMacro	LDNS_STATUS_INTERNAL_ERR
syn keyword ldnsMacro	LDNS_STATUS_INT_EXP
syn keyword ldnsMacro	LDNS_STATUS_ERR
syn keyword ldnsMacro	LDNS_STATUS_INVALID_IP4
syn keyword ldnsMacro	LDNS_STATUS_INVALID_IP6
syn keyword ldnsMacro	LDNS_STATUS_INVALID_STR
syn keyword ldnsMacro	LDNS_STATUS_INVALID_B64

" ldns/resolver.h
syn keyword  ldnsType	  	ldns_resolver

" ldns/rr.h 
syn keyword  ldnsType	  	ldns_rr_list 
syn keyword  ldnsType           ldns_rr_descriptor
syn keyword  ldnsType           ldns_rr
syn keyword  ldnsType           ldns_rr_type
syn keyword  ldnsType           ldns_rr_class
syn keyword  ldnsType		ldns_rr_compress

syn keyword  ldnsConstant	LDNS_RR_CLASS_IN
syn keyword  ldnsConstant	LDNS_RR_CLASS_CHAOS
syn keyword  ldnsConstant	LDNS_RR_CLASS_HS  
syn keyword  ldnsConstant	LDNS_RR_CLASS_ANY 

syn keyword  ldnsConstant LDNS_RR_TYPE_A          
syn keyword  ldnsConstant LDNS_RR_TYPE_NS        
syn keyword  ldnsConstant LDNS_RR_TYPE_MD       
syn keyword  ldnsConstant LDNS_RR_TYPE_MF         
syn keyword  ldnsConstant LDNS_RR_TYPE_CNAME     
syn keyword  ldnsConstant LDNS_RR_TYPE_SOA       
syn keyword  ldnsConstant LDNS_RR_TYPE_MB         
syn keyword  ldnsConstant LDNS_RR_TYPE_MG         
syn keyword  ldnsConstant LDNS_RR_TYPE_MR       
syn keyword  ldnsConstant LDNS_RR_TYPE_NULL       
syn keyword  ldnsConstant LDNS_RR_TYPE_WKS        
syn keyword  ldnsConstant LDNS_RR_TYPE_PTR        
syn keyword  ldnsConstant LDNS_RR_TYPE_HINFO      
syn keyword  ldnsConstant LDNS_RR_TYPE_MINFO      
syn keyword  ldnsConstant LDNS_RR_TYPE_MX         
syn keyword  ldnsConstant LDNS_RR_TYPE_TXT        
syn keyword  ldnsConstant LDNS_RR_TYPE_RP         
syn keyword  ldnsConstant LDNS_RR_TYPE_AFSDB      
syn keyword  ldnsConstant LDNS_RR_TYPE_X25        
syn keyword  ldnsConstant LDNS_RR_TYPE_ISDN       
syn keyword  ldnsConstant LDNS_RR_TYPE_RT         
syn keyword  ldnsConstant LDNS_RR_TYPE_NSAP       
syn keyword  ldnsConstant LDNS_RR_TYPE_SIG        
syn keyword  ldnsConstant LDNS_RR_TYPE_KEY        
syn keyword  ldnsConstant LDNS_RR_TYPE_PX         
syn keyword  ldnsConstant LDNS_RR_TYPE_AAAA       
syn keyword  ldnsConstant LDNS_RR_TYPE_LOC        
syn keyword  ldnsConstant LDNS_RR_TYPE_NXT        
syn keyword  ldnsConstant LDNS_RR_TYPE_SRV        
syn keyword  ldnsConstant LDNS_RR_TYPE_NAPTR      
syn keyword  ldnsConstant LDNS_RR_TYPE_KX         
syn keyword  ldnsConstant LDNS_RR_TYPE_CERT       
syn keyword  ldnsConstant LDNS_RR_TYPE_DNAME      
syn keyword  ldnsConstant LDNS_RR_TYPE_OPT        
syn keyword  ldnsConstant LDNS_RR_TYPE_APL        
syn keyword  ldnsConstant LDNS_RR_TYPE_DS         
syn keyword  ldnsConstant LDNS_RR_TYPE_SSHFP      
syn keyword  ldnsConstant LDNS_RR_TYPE_RRSIG      
syn keyword  ldnsConstant LDNS_RR_TYPE_NSEC       
syn keyword  ldnsConstant LDNS_RR_TYPE_DNSKEY     
syn keyword  ldnsConstant LDNS_RR_TYPE_TSIG       
syn keyword  ldnsConstant LDNS_RR_TYPE_IXFR       
syn keyword  ldnsConstant LDNS_RR_TYPE_AXFR       
syn keyword  ldnsConstant LDNS_RR_TYPE_MAILB      
syn keyword  ldnsConstant LDNS_RR_TYPE_MAILA      
syn keyword  ldnsConstant LDNS_RR_TYPE_ANY        
syn keyword  ldnsConstant MAX_LABELLEN     
syn keyword  ldnsConstant MAX_DOMAINLEN
syn keyword  ldnsConstant LDNS_RR_COMPRESS
syn keyword  ldnsConstant LDNS_RR_NO_COMPRESS

syn keyword  ldnsMacro	QHEADERSZ
syn keyword  ldnsMacro	RD_MASK
syn keyword  ldnsMacro	RD_SHIFT
syn keyword  ldnsMacro	LDNS_RD
syn keyword  ldnsMacro	RD_SET
syn keyword  ldnsMacro	RD_CLR
syn keyword  ldnsMacro  TC_MASK
syn keyword  ldnsMacro  TC_SHIFT
syn keyword  ldnsMacro	LDNS_TC
syn keyword  ldnsMacro	TC_SET
syn keyword  ldnsMacro	TC_CLR
syn keyword  ldnsMacro	AA_MASK
syn keyword  ldnsMacro	AA_SHIFT
syn keyword  ldnsMacro	LDNS_AA
syn keyword  ldnsMacro	AA_SET
syn keyword  ldnsMacro	AA_CLR
syn keyword  ldnsMacro	OPCODE_MASK
syn keyword  ldnsMacro	OPCODE_SHIFT
syn keyword  ldnsMacro	OPCODE
syn keyword  ldnsMacro	OPCODE_SET
syn keyword  ldnsMacro	QR_MASK
syn keyword  ldnsMacro	QR_SHIFT
syn keyword  ldnsMacro	LDNS_QR
syn keyword  ldnsMacro	QR_SET
syn keyword  ldnsMacro	QR_CLR
syn keyword  ldnsMacro	RCODE_MASK
syn keyword  ldnsMacro	RCODE_SHIFT
syn keyword  ldnsMacro	RCODE
syn keyword  ldnsMacro	RCODE_SET
syn keyword  ldnsMacro	CD_MASK
syn keyword  ldnsMacro	CD_SHIFT
syn keyword  ldnsMacro	LDNS_CD
syn keyword  ldnsMacro	CD_SET
syn keyword  ldnsMacro	CD_CLR
syn keyword  ldnsMacro	AD_MASK
syn keyword  ldnsMacro	AD_SHIFT
syn keyword  ldnsMacro	LDNS_AD
syn keyword  ldnsMacro	AD_SET
syn keyword  ldnsMacro	AD_CLR
syn keyword  ldnsMacro	Z_MASK
syn keyword  ldnsMacro	Z_SHIFT
syn keyword  ldnsMacro	LDNS_Z
syn keyword  ldnsMacro	Z_SET
syn keyword  ldnsMacro	Z_CLR
syn keyword  ldnsMacro	RA_MASK
syn keyword  ldnsMacro	RA_SHIFT
syn keyword  ldnsMacro	LDNS_RA
syn keyword  ldnsMacro	RA_SET
syn keyword  ldnsMacro	RA_CLR
syn keyword  ldnsMacro	LDNS_ID
syn keyword  ldnsMacro  QDCOUNT_OFF
syn keyword  ldnsMacro	QDCOUNT
syn keyword  ldnsMacro  ANCOUNT_OFF
syn keyword  ldnsMacro	ANCOUNT
syn keyword  ldnsMacro  NSCOUNT_OFF
syn keyword  ldnsMacro	NSCOUNT
syn keyword  ldnsMacro  ARCOUNT_OFF
syn keyword  ldnsMacro 	ARCOUNT

" ldns/buffer.h
syn keyword  ldnsType		ldns_buffer
syn keyword  ldnsConstant	MIN_BUFLEN

" ldns/host2str.h
syn keyword  ldnsType	ldns_lookup_table

" Default highlighting
command -nargs=+ HiLink hi def link <args>
HiLink ldnsType                Type
HiLink ldnsFunction            Function
HiLink ldnsMacro               Macro
HiLink ldnsConstant            Constant
delcommand HiLink
