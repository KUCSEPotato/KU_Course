module Lshift2(
	input[31:0] A,
	output[31:0] B);
	
 assign B=A[29:0];
 assign B[1:0]='b00;
endmodule