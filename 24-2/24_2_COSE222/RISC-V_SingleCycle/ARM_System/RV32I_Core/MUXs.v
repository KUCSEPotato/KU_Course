module mux3_32bit(
	input[31:0] A,
	input[31:0] B,
	input[31:0] C,
	input[1:0] select,
	output reg[31:0] out);  
 
 always @ (select or A or B or C)
   case(select)
     0 : out=A;
     1 : out=B;
     2 : out=C;
   endcase
endmodule

module mux16_2out_32bit(
	input[31:0] A,
	input[31:0] B,
	input[31:0] C,
	input[31:0] D,
	input[31:0] E,
	input[31:0] F,
	input[31:0] G,
	input[31:0] H,
	input[31:0] I,
	input[31:0] J,
	input[31:0] K,
	input[31:0] L,
	input[31:0] M,
	input[31:0] N,
	input[31:0] O,
	input[31:0] P,
	input[3:0] select1,
	input[3:0] select2,
	output reg[31:0] out1,
	output reg[31:0] out2);
	
 always @ (select1 or select2 or A or B or C or D or E or F or G or H or I or J or K or L or M or N or O or P) begin
   case(select1)
     0 : out1=A;
     1 : out1=B;
     2 : out1=C;
     3 : out1=D;
     4 : out1=E;
     5 : out1=F;
     6 : out1=G;
     7 : out1=H;
     8 : out1=I;
     9 : out1=J;
     10 : out1=K;
     11 : out1=L;
     12 : out1=M;
     13 : out1=N;
     14 : out1=O;
     15 : out1=P;
   endcase
   case(select2)
     0 : out2=A;
     1 : out2=B;
     2 : out2=C;
     3 : out2=D;
     4 : out2=E;
     5 : out2=F;
     6 : out2=G;
     7 : out2=H;
     8 : out2=I;
     9 : out2=J;
     10 : out2=K;
     11 : out2=L;
     12 : out2=M;
     13 : out2=N;
     14 : out2=O;
     15 : out2=P;
   endcase
  end
endmodule

module mux16_32bit(
	input[31:0] A,
	input[31:0] B,
	input[31:0] C,
	input[31:0] D,
	input[31:0] E,
	input[31:0] F,
	input[31:0] G,
	input[31:0] H,
	input[31:0] I,
	input[31:0] J,
	input[31:0] K,
	input[31:0] L,
	input[31:0] M,
	input[31:0] N,
	input[31:0] O,
	input[31:0] P,
	input[3:0] select,
	output reg[31:0] out);
	
 always @ (*)
   case(select)
     0 : out=A;
     1 : out=B;
     2 : out=C;
     3 : out=D;
     4 : out=E;
     5 : out=F;
     6 : out=G;
     7 : out=H;
     8 : out=I;
     9 : out=J;
     10 : out=K;
     11 : out=L;
     12 : out=M;
     13 : out=N;
     14 : out=O;
     15 : out=P;
   endcase
endmodule

module mux3_16bit(A,B,C,select,out);
 input [15:0]A,B,C;
 input [1:0] select;
 output reg [15:0] out;
 
 always @ (select or A or B or C)
   case(select)
     0 : out=A;
     1 : out=B;
     2 : out=C;
   endcase
endmodule

module mux3_4bit(A,B,C,select,out);
 input [3:0]A,B,C;
 input [1:0] select;
 output reg [3:0] out;
 always @ (select or A or B or C)
   case(select)
     0 : out=A;
     1 : out=B;
     2 : out=C;
   endcase
endmodule

module mux6_32bit(
	input[31:0] A,
	input[31:0] B,
	input[31:0] C,
	input[31:0] D,
	input[31:0] E,
	input[31:0] F,
	input[2:0] select,
	output reg[31:0] out);
 
 always @ (select or A or B or C or D or E or F)
   case(select)
     0 : out=A;
     1 : out=B;
     2 : out=C;
     3 : out=D;
     4 : out=E;
     5 : out=F;
   endcase
endmodule
   
module mux4_32bit(A,B,C,D,select,out);  
 input [31:0]A,B,C,D;
 input [1:0] select;
 output reg [31:0] out;
  always @ (*)
   case(select)
     0 : out=A;
     1 : out=B;
     2 : out=C;
     3 : out=D;
   endcase
endmodule