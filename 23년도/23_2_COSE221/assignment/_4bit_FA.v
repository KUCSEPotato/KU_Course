module _4bit_FA(
	input [3:0] a,
	input [3:0] b,
	input cin,
    output [3:0]s,
    output cout
);
	wire [3:0] co;
	assign cout=co[3];
    _1bit_FA FA0(.a(a[0]), .b(b[0]), .cin(cin),   .s(s[0]), .cout(co[0]));
    _1bit_FA FA1(.a(a[1]), .b(b[1]), .cin(co[0]), .s(s[1]), .cout(co[1]));
    _1bit_FA FA2(.a(a[2]), .b(b[2]), .cin(co[1]), .s(s[2]), .cout(co[2]));
    _1bit_FA FA3(.a(a[3]), .b(b[3]), .cin(co[2]), .s(s[3]), .cout(co[3]));

endmodule


module _1bit_FA(
    input a,
    input b,
    input cin,
    output s,
    output cout
);
    assign cout = ((a^b)&cin)|(a&b);  //(a&b)|(b&cin)|(cin&a);
    assign s = a^b^cin;
endmodule
