" source /home/miekg/.vim/syntax/ldns.vim
" Vim syntax file
" Language:     C libdns
" Maintainer:   miekg
" Last change:  2004-12-15

" ldns/rdata.h
syn keyword  ldnsType           t_rdata_field
syn keyword  ldnsType           t_rr
syn keyword  ldnsType           ldns_rdata_field_type
syn keyword  ldnsType           ldns_rr_descriptor_type
syn keyword  ldnsType           ldns_header_type
syn keyword  ldnsType           ldns_packet_type
syn keyword  ldnsType           t_rrset
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

" Default highlighting
command -nargs=+ HiLink hi def link <args>
HiLink ldnsType                Type
HiLink ldnsFunction            Function
HiLink ldnsMacro               Macro
HiLink ldnsConstant            Constant
delcommand HiLink
