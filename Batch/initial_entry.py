import sys
def generate_rules(length):
    for i in range(1,length+1):
        fw = open("rules/"+i+"-commands.txt","w")
        fw.write("table_clear tbl_determine_task\n")
        fw.write("table_clear tbl_do_telemetry_level_0\n")
        fw.write("table_clear tbl_forward\n")
        fw.write("table_clear tbl_ttl_rules\n")
        fw.write("\n")
        for j in range(1,4):
            fw.write("able_add tbl_do_telemetry_level_0 write_task_"+j+"_value "+j+' => '+j+'\n')
        fw.write("\n")
        for j in range(1,length+1):
            if j<=i:
                fw.write("table_add tbl_forward forward 10.0.0."+(int)(j-1)+" => 1")
            else:
                fw.write("table_add tbl_forward forward 10.0.0."+(int)(j-1)+" => 2")
        fw.write("\n")
        global_hash_range = 100000
        for hop in range(1, 10):
                fw.write("table_add tbl_ttl_rules get_approximation " + str(hop) + " => " + str(int(global_hash_range // hop)) + "\n")
        fw.write("\n")
        if i == 1 :
            fw.write("table_add tbl_determine_task write_task_3 0->16 => 0\n")
            fw.write("table_add tbl_determine_task write_task_2 17->48 => 0\n")
            fw.write("table_add tbl_determine_task write_task_1 48->99 => 0\n")

if __name__ == '__main__':
    length = int(sys.argv[1])