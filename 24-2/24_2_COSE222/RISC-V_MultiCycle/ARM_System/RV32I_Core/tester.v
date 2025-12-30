module tester(
	input clk,
	input reset,
	output[31:0] pc,
	input[31:0] instr,
	input nIRQ,
	input be,
	output[31:0] memaddrM,
	output memwriteM,
	output memreadM,
	output[31:0] writedataM,
	input[31:0] readdata);
	
	
	assign pc=0;
	assign memaddrM=0;
	assign memwriteM=1;
	assign memreadM=0;
	assign writedataM=50;
	
endmodule