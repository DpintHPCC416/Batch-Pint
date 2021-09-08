#include <core.p4>
#include <v1model.p4>
#define ETHERTYPE_IPV4 0x0800
#define PROTOCOL_DPINT 125
#define DECIDER_HASH_UPBOUND 100
#define GLOBAL_HASH_UPBOUND 100000
#define QUERY_NUMBER 3

header ethernet_h
{
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}


header ipv4_h
{
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header dpint_h
{
    bit<16> hop;
    bit<16> task;    
    bit<32> value;   
}

struct headers
{
    ethernet_h ethernet;
    ipv4_h ipv4;
    dpint_h dpint;
}


struct dpint_metadata_t{
    bit<32> telemetry_value_timestamp;
    bit<32> telemetry_value_switch_id;
    bit<32> telemetry_value_enq_qdepth;

    bit<32> decider_hash;
    bit<48> global_hash;
    bit<48> approximation;
    bit<32> count; 
    bit<1> switch_is_sink;
    bit<1> flow_global_write_or_not;
}

parser IngressParser(packet_in pkt,
                    out headers hdr,
                    inout dpint_metadata_t dp_meta,
                    inout standard_metadata_t standard_metadata
)
{
    state start{
        transition parse_ethernet;
    }
    
    state parse_ethernet
    {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType)
        {
            ETHERTYPE_IPV4: parse_ipv4;
            _:accept;
        }
    }

    state parse_ipv4
    {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol)
        {
            PROTOCOL_DPINT: parse_dpint;
            _:accept;
        }
    }

    state parse_dpint
    {
        pkt.extract(hdr.dpint);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout dpint_metadata_t dp_meta) {
    apply {  }
}


control source_control(inout headers hdr,inout dpint_metadata_t dp_meta)    
{
    action write_task_1()      
    {
        hdr.dpint.task = 0x1; 
    }
    action write_task_2()
    {
        hdr.dpint.task = 0x2;
    }
    action write_task_3()
    {
        hdr.dpint.task = 0x3;
    }
    table tbl_determine_task
    {
        key = {
            dp_meta.decider_hash:range;
        }
    
    actions = {
        write_task_1;
        write_task_2;
        write_task_3;
        NoAction;
    }
    }
    apply
    {
        tbl_determine_task.apply();
    }
}

control DpintControl(inout headers hdr, inout dpint_metadata_t dp_meta,inout standard_metadata_t standard_metadata)
{
    action write_task_1_value(bit<32> switch_id)    
    {
        if(dp_meta.flow_global_write_or_not == 1 )
        {
            hdr.dpint.value = switch_id;
        }
    }

    action write_task_2_value(bit<32> switch_id)
    {
        if(dp_meta.flow_global_write_or_not == 1 )
        {
            hdr.dpint.value = standard_metadata.enq_timestamp;
        }
    }

    action write_task_3_value(bit<32> switch_id)
    {
        if(dp_meta.flow_global_write_or_not == 1)
        {
            hdr.dpint.value = (bit<32>)standard_metadata.enq_qdepth;     
        }
    }

    table tbl_do_telemetry_level_0
    {
        key = 
        {
            hdr.dpint.task: exact;
        }
        actions =
        {
            write_task_1_value;
            write_task_2_value;
            write_task_3_value;
        }
    }
        apply
        {
            tbl_do_telemetry_level_0.apply();
        }
    

}

control DpintIngress(inout headers hdr, inout dpint_metadata_t dp_meta, inout standard_metadata_t standard_metadata)
{
    source_control() ctl_source_control;
    DpintControl() ctl_DpintControl;
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action add_dpint_header()
    {
        hdr.ipv4.protocol = PROTOCOL_DPINT;
        hdr.dpint.setValid();
        hdr.dpint.task = 0;
        hdr.dpint.value = 0;
    }

    action forward(bit<9> egress_port)
    {
        hdr.ipv4.ecn = 1;
        standard_metadata.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.dpint.hop = hdr.dpint.hop + 1;
    }

    table tbl_forward
    {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = 
        {
            forward;
            drop;
        }
    }

    action get_approximation(bit<48> approximation)
    {
        dp_meta.approximation = approximation;
    }

    table tbl_ttl_rules
    {
        key = {
            hdr.dpint.hop: exact;
        }
        actions = 
        {
            get_approximation;
            NoAction;
        }
        default_action = NoAction;
    }

    apply
    {
        bit<32> diff = 256 - (bit<32>)hdr.ipv4.ttl;
        hash(dp_meta.global_hash,HashAlgorithm.crc32,(bit<1>)0,{hdr.ipv4.srcAddr,hdr.ipv4.identification,hdr.ipv4.dstAddr,diff},(bit<48>)GLOBAL_HASH_UPBOUND);
       
        hash(dp_meta.decider_hash,HashAlgorithm.crc32,(bit<1>)0,{hdr.ipv4.srcAddr,hdr.ipv4.dstAddr,hdr.ipv4.identification},(bit<32>)DECIDER_HASH_UPBOUND);
        if(hdr.ipv4.isValid())     
        {
            if(!hdr.dpint.isValid())
            {
                add_dpint_header();
                ctl_source_control.apply(hdr,dp_meta);
            }
        }

        tbl_forward.apply();
        tbl_ttl_rules.apply();     
        if(dp_meta.global_hash < dp_meta.approximation)
            dp_meta.flow_global_write_or_not = 1;
        ctl_DpintControl.apply(hdr,dp_meta,standard_metadata);
    }
}




control MyComputeChecksum(inout headers  hdr, inout dpint_metadata_t dp_meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out pkt, in headers hdr)
{
    apply{
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.dpint);
    }
    
}



control MyEgress(inout headers hdr, inout dpint_metadata_t dp_meta, inout standard_metadata_t standard_metadata)
{
    apply{

    }
}

V1Switch(
    IngressParser(),
    MyVerifyChecksum(),
    DpintIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
)main;