" Vim syntax file
" Language:     C libdns
" Maintainer:   miekg
" Last change:  2004-12-15

" ldns/rdata.h
syn keyword  ldnsType           ldns_rdf_type
syn keyword  ldnsType           ldns_rdf
syn keyword  ldnsType           ldns_rr
syn keyword  ldnsType           ldns_rr_descriptor
syn keyword  ldnsType           ldns_hdr
syn keyword  ldnsType           ldns_pkt
syn keyword  ldnsType           ldns_status
syn keyword  ldnsType           ldns_rrset
syn keyword  ldnsType           ldns_class
syn keyword  ldnsConstant       true
syn keyword  ldnsConstant       false

" dns/error.h
syn keyword ldnsMacro	LDNS_STATUS_OK
syn keyword ldnsMacro	LDNS_STATUS_EMPTY_LABEL
syn keyword ldnsMacro	LDNS_STATUS_LABEL_OVERFLOW
syn keyword ldnsMacro	LDNS_STATUS_DOMAINNAME_OVERFLOW
syn keyword ldnsMacro	LDNS_STATUS_DDD_OVERFLOW
syn keyword ldnsMacro	LDNS_STATUS_PACKET_OVERFLOW
syn keyword ldnsMacro	LDNS_STATUS_INVALID_POINTER
syn keyword ldnsMacro	LDNS_STATUS_MEM_ERR
syn keyword ldnsMacro	LDNS_STATUS_INTERNAL_ERR
syn keyword ldnsMacro	LDNS_STATUS_INT_EXP
syn keyword ldnsMacro	LDNS_STATUS_ERR

" ldns/rr.h 
syn keyword  ldnsConstant TYPE_A          
syn keyword  ldnsConstant TYPE_NS        
syn keyword  ldnsConstant TYPE_MD       
syn keyword  ldnsConstant TYPE_MF         
syn keyword  ldnsConstant TYPE_CNAME     
syn keyword  ldnsConstant TYPE_SOA       
syn keyword  ldnsConstant TYPE_MB         
syn keyword  ldnsConstant TYPE_MG         
syn keyword  ldnsConstant TYPE_MR       
syn keyword  ldnsConstant TYPE_NULL       
syn keyword  ldnsConstant TYPE_WKS        
syn keyword  ldnsConstant TYPE_PTR        
syn keyword  ldnsConstant TYPE_HINFO      
syn keyword  ldnsConstant TYPE_MINFO      
syn keyword  ldnsConstant TYPE_MX         
syn keyword  ldnsConstant TYPE_TXT        
syn keyword  ldnsConstant TYPE_RP         
syn keyword  ldnsConstant TYPE_AFSDB      
syn keyword  ldnsConstant TYPE_X25        
syn keyword  ldnsConstant TYPE_ISDN       
syn keyword  ldnsConstant TYPE_RT         
syn keyword  ldnsConstant TYPE_NSAP       
syn keyword  ldnsConstant TYPE_SIG        
syn keyword  ldnsConstant TYPE_KEY        
syn keyword  ldnsConstant TYPE_PX         
syn keyword  ldnsConstant TYPE_AAAA       
syn keyword  ldnsConstant TYPE_LOC        
syn keyword  ldnsConstant TYPE_NXT        
syn keyword  ldnsConstant TYPE_SRV        
syn keyword  ldnsConstant TYPE_NAPTR      
syn keyword  ldnsConstant TYPE_KX         
syn keyword  ldnsConstant TYPE_CERT       
syn keyword  ldnsConstant TYPE_DNAME      
syn keyword  ldnsConstant TYPE_OPT        
syn keyword  ldnsConstant TYPE_APL        
syn keyword  ldnsConstant TYPE_DS         
syn keyword  ldnsConstant TYPE_SSHFP      
syn keyword  ldnsConstant TYPE_RRSIG      
syn keyword  ldnsConstant TYPE_NSEC       
syn keyword  ldnsConstant TYPE_DNSKEY     
syn keyword  ldnsConstant TYPE_TSIG       
syn keyword  ldnsConstant TYPE_IXFR       
syn keyword  ldnsConstant TYPE_AXFR       
syn keyword  ldnsConstant TYPE_MAILB      
syn keyword  ldnsConstant TYPE_MAILA      
syn keyword  ldnsConstant TYPE_ANY        
syn keyword  ldnsConstant MAXLABELLEN     
syn keyword  ldnsConstant MAXDOMAINLEN


syn keyword  ldnsMacro	QHEADERSZ
syn keyword  ldnsMacro	RD_MASK
syn keyword  ldnsMacro	RD_SHIFT
syn keyword  ldnsMacro	RD
syn keyword  ldnsMacro	RD_SET
syn keyword  ldnsMacro	RD_CLR
syn keyword  ldnsMacro  TC_MASK
syn keyword  ldnsMacro  TC_SHIFT
syn keyword  ldnsMacro	TC
syn keyword  ldnsMacro	TC_SET
syn keyword  ldnsMacro	TC_CLR
syn keyword  ldnsMacro	AA_MASK
syn keyword  ldnsMacro	AA_SHIFT
syn keyword  ldnsMacro	AA
syn keyword  ldnsMacro	AA_SET
syn keyword  ldnsMacro	AA_CLR
syn keyword  ldnsMacro	OPCODE_MASK
syn keyword  ldnsMacro	OPCODE_SHIFT
syn keyword  ldnsMacro	OPCODE
syn keyword  ldnsMacro	OPCODE_SET
syn keyword  ldnsMacro	QR_MASK
syn keyword  ldnsMacro	QR_SHIFT
syn keyword  ldnsMacro	QR
syn keyword  ldnsMacro	QR_SET
syn keyword  ldnsMacro	QR_CLR
syn keyword  ldnsMacro	RCODE_MASK
syn keyword  ldnsMacro	RCODE_SHIFT
syn keyword  ldnsMacro	RCODE
syn keyword  ldnsMacro	RCODE_SET
syn keyword  ldnsMacro	CD_MASK
syn keyword  ldnsMacro	CD_SHIFT
syn keyword  ldnsMacro	CD
syn keyword  ldnsMacro	CD_SET
syn keyword  ldnsMacro	CD_CLR
syn keyword  ldnsMacro	AD_MASK
syn keyword  ldnsMacro	AD_SHIFT
syn keyword  ldnsMacro	AD
syn keyword  ldnsMacro	AD_SET
syn keyword  ldnsMacro	AD_CLR
syn keyword  ldnsMacro	Z_MASK
syn keyword  ldnsMacro	Z_SHIFT
syn keyword  ldnsMacro	Z
syn keyword  ldnsMacro	Z_SET
syn keyword  ldnsMacro	Z_CLR
syn keyword  ldnsMacro	RA_MASK
syn keyword  ldnsMacro	RA_SHIFT
syn keyword  ldnsMacro	RA
syn keyword  ldnsMacro	RA_SET
syn keyword  ldnsMacro	RA_CLR
syn keyword  ldnsMacro	ID
syn keyword  ldnsMacro  QDCOUNT_OFF
syn keyword  ldnsMacro	QDCOUNT
syn keyword  ldnsMacro  ANCOUNT_OFF
syn keyword  ldnsMacro	ANCOUNT
syn keyword  ldnsMacro  NSCOUNT_OFF
syn keyword  ldnsMacro	NSCOUNT
syn keyword  ldnsMacro  ARCOUNT_OFF
syn keyword  ldnsMacro 	ARCOUNT

" Default highlighting
command -nargs=+ HiLink hi def link <args>
HiLink ldnsType                Type
HiLink ldnsFunction            Function
HiLink ldnsMacro               Macro
HiLink ldnsConstant            Constant
delcommand HiLink
