module regfile(
	input [3:0] num1,
	input [3:0]num2,
	input [3:0]writenum,
	input write,
	input clk,
	input reset,
	input [31:0] regin,
	output [31:0] regout1,
	output [31:0] regout2,
	output [31:0] pc);
	
	reg[31:0] register[15:0];

	integer i;
	always @ (posedge clk or negedge reset)
	if(~reset)
		for(i=0;i<16;i=i+1) register[i]<='h00000000;
	else if(write)
		register[writenum]<=regin;
		
	assign regout1=register[num1];
	assign regout2=register[num2];
	assign pc=register[15];
 endmodule