#include <core.p4>
#include <v1model.p4>
#define ETHERTYPE_IPV4 0x0800
#define PROTOCOL_DPINT 125
#define DECIDER_HASH_UPBOUND 999
#define GLOBAL_HASH_UPBOUND 65535
#define QUERY_NUMBER 4
#define BATCH_NUMBER 5
#define FLOW_ID_UPBOUND 65535
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
    bit<8> protocol;
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
    bit<32> out_port;
    bit<32> decider_hash;
    bit<48> global_hash;
    bit<48> approximation;
    bit<32> count; 
    bit<1> switch_is_sink;
    bit<1> flow_global_write_or_not;
    bit<32> flow_ID;
    bit<32> inter_arrival_time;
    bit<32> flow_forward_number;
    bit<32> switch_forward_number;
    bit<32> port_packet_number;
    bit<1> goto_tbl_check_inport;
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

//dicide which task to do depending on the decider hash value
control source_control(inout headers hdr,inout dpint_metadata_t dp_meta)    //决定写什么任务
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
    action write_task_4()
    {
        hdr.dpint.task = 0x4;
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
        write_task_4;
        NoAction;
    }
    }
    apply
    {
        tbl_determine_task.apply();
    }
}
// Measure and write to packet
control DpintControl(inout headers hdr, inout dpint_metadata_t dp_meta,inout standard_metadata_t standard_metadata)
{

    
    action write_task_1_value()
    {
        if(dp_meta.flow_global_write_or_not == 1 && hdr.dpint.task != 0 )
        {
            hdr.dpint.value = dp_meta.flow_forward_number;
            hdr.dpint.hop = 255 - (bit<16>)hdr.ipv4.ttl;
        }
    }

    action write_task_2_value()
    {
        if(dp_meta.flow_global_write_or_not == 1 && hdr.dpint.task != 0 )
        {
            hdr.dpint.value = dp_meta.inter_arrival_time;
            hdr.dpint.hop = 255 - (bit<16>)hdr.ipv4.ttl;
        }
    }

    action write_task_3_value()
    {
        if(dp_meta.flow_global_write_or_not == 1 && hdr.dpint.task != 0 )
        {
            hdr.dpint.value = dp_meta.flow_forward_number;
            hdr.dpint.hop = 255 - (bit<16>)hdr.ipv4.ttl;
        }
    }

    action write_task_4_value(bit<32> Switch_ID)
    {
        if(dp_meta.flow_global_write_or_not == 1 && hdr.dpint.task != 0)
        {
            hdr.dpint.value = Switch_ID;
            hdr.dpint.hop = 255 - (bit<16>)hdr.ipv4.ttl;
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
            write_task_4_value;
        }
    }
    register <bit<48>> (65535) global_timestamp_reg;     //last global timestamp  //because every flow need to update a timestamp when each packet arrives
    register <bit<32>> (65535) flow_packet_number;     //packet number of a flow

    apply
    {
        //timestamp
        if(hdr.dpint.task != 0)
        {
            bit<48> last_global_timestamp;
            global_timestamp_reg.read(last_global_timestamp,dp_meta.flow_ID);
            dp_meta.inter_arrival_time = (bit<32>)(standard_metadata.ingress_global_timestamp - last_global_timestamp);
            global_timestamp_reg.write(dp_meta.flow_ID,standard_metadata.ingress_global_timestamp);
            //flow forward number
            flow_packet_number.read(dp_meta.flow_forward_number,dp_meta.flow_ID);
            dp_meta.flow_forward_number = dp_meta.flow_forward_number+1;
            flow_packet_number.write(dp_meta.flow_ID,dp_meta.flow_forward_number);

        }
        tbl_do_telemetry_level_0.apply();
    }
    

}

control DpintIngress(inout headers hdr, inout dpint_metadata_t dp_meta, inout standard_metadata_t standard_metadata)
{
    source_control() ctl_source_control;
   
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action add_dpint_header()
    {
        hdr.dpint.setValid();
        hdr.dpint.task = 0;
        hdr.dpint.value = 0;
        hdr.dpint.protocol = hdr.ipv4.protocol;
        hdr.ipv4.protocol = PROTOCOL_DPINT;
    }

    action forward(bit<48> dstAddr ,bit<9> port)
    {
        dp_meta.goto_tbl_check_inport = 0;
        hdr.ipv4.ecn = 1;
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        dp_meta.out_port = (bit<32>)port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action goto_tbl_check_inport()
    {
        dp_meta.goto_tbl_check_inport = 1;
    }
    table tbl_forward
    {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = 
        {
            forward;
            drop;
            NoAction;
            goto_tbl_check_inport;
        }
        default_action = drop();
    }

    table tbl_check_inport
    {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        default_action = drop();
    }
    

    

    register <bit<4>> (65535) query_counter;    
    register <bit<32>> (65535) last_hash;
    apply
    {   
        bit<32> diff = 256 - (bit<32>)hdr.ipv4.ttl;
        //get flowID index from hash(five-tuple)
        hash(dp_meta.flow_ID, HashAlgorithm.crc32, (bit<1>)0, {hdr.ipv4.protocol,hdr.ipv4.srcAddr,hdr.ipv4.dstAddr},(bit<48>)FLOW_ID_UPBOUND);
        //get global hash value from hash(five-tuple + diff)
        hash(dp_meta.global_hash,HashAlgorithm.crc32,(bit<1>)0,{hdr.ipv4.srcAddr,hdr.ipv4.identification,hdr.ipv4.dstAddr,diff},(bit<48>)GLOBAL_HASH_UPBOUND);
    
        if(hdr.ipv4.isValid())      
        {
            
            if(!hdr.dpint.isValid() && hdr.ipv4.ttl == 255)
            {
                add_dpint_header();
                bit<4> query_count;
                query_counter.read(query_count,(bit<32>)dp_meta.flow_ID);
                if(query_count == BATCH_NUMBER || query_count == 0)
                {
                    hash(dp_meta.decider_hash,HashAlgorithm.random,(bit<1>)0,{hdr.ipv4.srcAddr,hdr.ipv4.dstAddr,hdr.ipv4.identification},(bit<32>)DECIDER_HASH_UPBOUND);
                    last_hash.write((bit<32>)dp_meta.flow_ID,dp_meta.decider_hash); //FIXME: why writting??
                    query_counter.write((bit<32>)dp_meta.flow_ID,1);
                }
                else
                {
                    last_hash.read(dp_meta.decider_hash,(bit<32>)dp_meta.flow_ID);
                    query_counter.write((bit<32>)dp_meta.flow_ID,query_count+1);
                }
                //deciding task to do 
                ctl_source_control.apply(hdr,dp_meta);
            }
        }

        tbl_forward.apply();
        if(dp_meta.goto_tbl_check_inport == 1)
            tbl_check_inport.apply();
        
        
    }
}



//下面的还没检查

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
    DpintControl() ctl_DpintControl;
    action get_approximation(bit<48> approximation)
    {
        dp_meta.approximation = approximation;
    }

    table tbl_ttl_rules
    {
        key = {
            hdr.ipv4.ttl: exact;
        }
        actions = 
        {
            get_approximation;
            NoAction;
        }
        default_action = NoAction;
    }
    action drop_dpint_header()
    {
        hdr.ipv4.protocol = hdr.dpint.protocol;
        hdr.ipv4.ecn = 0;
        hdr.dpint.setInvalid();
    }

    table tbl_check_last_hop
    {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = 
        {
            drop_dpint_header;
            NoAction;
        }
        default_action = NoAction;
    }
    apply{
        
        tbl_ttl_rules.apply();     
        //check write or not
        if(dp_meta.global_hash < dp_meta.approximation)
            dp_meta.flow_global_write_or_not = 1;
        else
            dp_meta.flow_global_write_or_not = 0;
        ctl_DpintControl.apply(hdr,dp_meta,standard_metadata);
        tbl_check_last_hop.apply();
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