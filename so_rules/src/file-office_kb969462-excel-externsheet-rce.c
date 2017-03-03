/*
  DOES NOT USE THE BUILT-IN DETECTION FUNCTIONALITY!!!
  
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"WEB-CLIENT Microsoft Office Excel ExternSheet record remote code execution attempt"; flowbits:isset,file.xls; flow:to_client,established; content:"|17 00|"; metadata:policy balanced-ips drop, policy security-ips drop, service http; reference:cve,2009-0558; reference:url,technet.microsoft.com/en-us/security/bulletin/MS09-021; classtype:attempted-user; sid:15521; rev:1;)
*/
/*
 * Use at your own risk.
 *
 * Copyright (C) 2005-2008 Sourcefire, Inc.
 * 
 * This file is autogenerated via rules2c, by Brian Caswell <bmc@sourcefire.com>
 */


#include "sf_snort_plugin_api.h"
#include "sf_snort_packet.h"

#include "so-util.h"

//#define DEBUG 1
#ifdef DEBUG
#define DEBUG_WRAP(code) code
#else
#define DEBUG_WRAP(code)
#endif

/* declare detection functions */
int rule15521eval(void *p);

/* declare rule data structures */
/* precompile the stuff that needs pre-compiled */
/* flowbits:isset "file.xls"; */
static FlowBitsInfo rule15521flowbits0 =
{
    "file.xls",
    FLOWBIT_ISSET,
    0,
};

static RuleOption rule15521option0 =
{
    OPTION_TYPE_FLOWBIT,
    {
        &rule15521flowbits0
    }
};
/* flow:established, to_client; */
static FlowFlags rule15521flow1 = 
{
    FLOW_ESTABLISHED|FLOW_TO_CLIENT
};

static RuleOption rule15521option1 =
{
    OPTION_TYPE_FLOWFLAGS,
    {
        &rule15521flow1
    }
};
// content:"|17 00|", depth 0; 
static ContentInfo rule15521content2 = 
{
    (uint8_t *) "|17 00|", /* pattern (now in snort content format) */
    0, /* depth */
    0, /* offset */
    CONTENT_BUF_NORMALIZED|CONTENT_RELATIVE, /* flags */
    NULL, /* holder for boyer/moore PTR */
    NULL, /* more holder info - byteform */
    0, /* byteform length */
    0 /* increment length*/
};

static RuleOption rule15521option2 = 
{
    OPTION_TYPE_CONTENT,
    {
        &rule15521content2
    }
};

/* references for sid 15521 */
/* reference: cve "2009-0558"; */
static RuleReference rule15521ref1 = 
{
    "cve", /* type */
    "2009-0558" /* value */
};

/* reference: url "technet.microsoft.com/en-us/security/bulletin/MS09-021"; */
static RuleReference rule15521ref2 = 
{
    "url", /* type */
    "technet.microsoft.com/en-us/security/bulletin/MS09-021" /* value */
};

static RuleReference *rule15521refs[] =
{
    &rule15521ref1,
    &rule15521ref2,
    NULL
};
/* metadata for sid 15521 */
/* metadata:service http, policy balanced-ips drop, policy security-ips drop; */
static RuleMetaData rule15521service1 = 
{
    "service http"
};


//static RuleMetaData rule15521policy1 = 
//{
//    "policy balanced-ips drop"
//};
//
//static RuleMetaData rule15521policy2 = 
//{
//    "policy security-ips drop"
//};


static RuleMetaData *rule15521metadata[] =
{
    &rule15521service1,
//    &rule15521policy1,
//    &rule15521policy2,
    NULL
};

RuleOption *rule15521options[] =
{
    &rule15521option0,
    &rule15521option1,
    &rule15521option2,
    NULL
};

Rule rule15521 = {
   
   /* rule header, akin to => tcp any any -> any any               */{
       IPPROTO_TCP, /* proto */
       "$EXTERNAL_NET", /* SRCIP     */
       "$HTTP_PORTS", /* SRCPORT   */
   
       0, /* DIRECTION */
       "$HOME_NET", /* DSTIP     */
   
       "any", /* DSTPORT   */
   },
   /* metadata */
   { 
       3,  /* genid */
       15521, /* sigid */
       9, /* revision */
   
       "attempted-user", /* classification */
       0,  /* hardcoded priority XXX NOT PROVIDED BY GRAMMAR YET! */
       "FILE-OFFICE Microsoft Office Excel ExternSheet record remote code execution attempt",     /* message */
       rule15521refs /* ptr to references */
       ,rule15521metadata
   },
   rule15521options, /* ptr to rule options */
   &rule15521eval, /* DO NOT use the built in detection function */
   0 /* am I initialized yet? */
};


/* detection functions */
int rule15521eval(void *p) {
    const uint8_t *cursor_normal = 0;
    SFSnortPacket *sp = (SFSnortPacket *) p;

    const uint8_t *end_of_payload;
    const uint8_t *cursor_detect;

    uint16_t record_size;
    uint16_t record_type;
    uint16_t cgXTI;      // the number of elements in the rgXTI array
    uint16_t iXTI;       // an XtiIndex that specifies the XTI array entry    
    uint8_t  cch;        // name size
    
    DEBUG_WRAP(const char *name="rule15521eval";)
    DEBUG_WRAP(printf("%s: enter\n", name);)

    if(sp == NULL)
        return RULE_NOMATCH;

    if(sp->payload == NULL)
        return RULE_NOMATCH;
    
    // flowbits:isset "file.xls";
    if (processFlowbits(p, rule15521options[0]->option_u.flowBit) > 0) {
        // flow:established, to_client;
        if (checkFlow(p, rule15521options[1]->option_u.flowFlags) > 0 ) {

            if(getBuffer(sp, CONTENT_BUF_NORMALIZED, &cursor_normal, &end_of_payload) <= 0)
               return RULE_NOMATCH;

            // content:"|17 00|", depth 0;
            while (contentMatch(p, rule15521options[2]->option_u.content, &cursor_normal) > 0)
            {
                DEBUG_WRAP(printf("%s: ExternSheet type 0x17 found\n", name);)
                    
                if (cursor_normal + 4 > end_of_payload)
                    return RULE_NOMATCH;


                cursor_detect = cursor_normal;                                
                record_size   = read_little_16(cursor_detect);  // ExternSheet record size
                DEBUG_WRAP(printf("%s: record_size 0x%04x\n", name, record_size);)

                if (record_size < 2) // record_size must be greater than or equal to 2
                    continue;
                        
                cursor_detect += 2;
                
                cgXTI = read_little_16(cursor_detect);  // the count of XTI records
                DEBUG_WRAP(printf("%s: cgXTI 0x%04x\n", name, cgXTI);)
                    
                cursor_detect += record_size;  // move to the next record of ExternSheet

                // Loop for records, now with integer overflow protection!
                while ((cursor_detect + 7 < end_of_payload) && (cursor_detect >= cursor_normal))
                {
                    record_type = read_little_16(cursor_detect);                    
                    cursor_detect += 2;
                    DEBUG_WRAP(printf("%s: record_type 0x%04x\n", name, record_type);)

                    record_size = read_little_16(cursor_detect);                    
                    cursor_detect += 2;
                    DEBUG_WRAP(printf("%s: record_size 0x%04x\n", name, record_size);)

                    if (record_type == 0x18)        // 0x18 == Lbl record type
                    {                        
                        cursor_detect += 3;         // 3 = Flags(2) + chKey(1)

                        // check if we have enough room for all these bytes before we start parsing
                        // the structure is 12 bytes plus a variable length name and array
                        if (cursor_detect + 12 > end_of_payload)
                           return RULE_NOMATCH;

                        cch = *cursor_detect;

                        // make sure all the reserved fields are null
                        // structure is this
                        //                       3,4                    7            8            9           10
                        // cch(1) cce(2) reserved3(2) itab(2) reserved4(1) reserved5(1) reserved6(1) reserved7(1) A(1)

                        // Since we are checking for NULL, it's okay to do a typecast because byte order doesn't matter
                        // Also, since we are checking everything for NULL, I'm combining them into single reads for speed
                        // On fail, skip to the next record and continue
                        if(*((uint16_t*)(cursor_detect + 3)) != 0) { // Byte order doesn't matter
                           cursor_detect += record_size;
                           continue;
                        }

                        if(*((uint32_t*)(cursor_detect + 7)) != 0) { // Byte order doesn't matter
                           cursor_detect += record_size;
                           continue;
                        }

                        cursor_detect += 13 + cch;  // 12 = cch(1) + cce(2) + reserved3(2) + itab(2) + reserved4(1) + reserved5(1) + reserved6(1) + reserved7(1) + A(1) + Name(cch) + rgce[0]                        
                        DEBUG_WRAP(printf("%s: cch 0x%02x\n", name, cch);)                            
                        
                        if (cursor_detect + 2 > end_of_payload)
                            return RULE_NOMATCH;

                        iXTI = read_little_16(cursor_detect);
                        
                        DEBUG_WRAP(printf("%s: rgce[0]=0x%x iXTI=0x%04x\n", name, *(cursor_detect - 1), iXTI);)
                            
                        if (*(cursor_detect - 1) == 0x3b && iXTI > cgXTI)   // if (rgce[0] == 0x3b && ..) 
                            return RULE_MATCH;
                        
                        cursor_detect += record_size;
                    }
                    else if (record_type == 0x3C) // 0x3C = Continue record type
                    {
                        DEBUG_WRAP(printf("%s: Continue record\n", name);)
                        cursor_detect += record_size;
                    }
                    else
                    {
                        DEBUG_WRAP(printf("Unexpected record type\n");)
                        break; // unexpected record type
                    }
                }
            }
        }
    }
    return RULE_NOMATCH;
}

/*
Rule *rules[] = {
    &rule15521,
    NULL
};
*/
