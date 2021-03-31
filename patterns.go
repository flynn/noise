package noise

var HandshakeNN = HandshakePattern{
	Name: "NN",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE},
	},
}

var HandshakeKN = HandshakePattern{
	Name:                 "KN",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

var HandshakeNK = HandshakePattern{
	Name:                 "NK",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES},
		{MessagePatternE, MessagePatternDHEE},
	},
}

var HandshakeKK = HandshakePattern{
	Name:                 "KK",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternDHSS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

var HandshakeNX = HandshakePattern{
	Name: "NX",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternS, MessagePatternDHES},
	},
}

var HandshakeKX = HandshakePattern{
	Name:                 "KX",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE, MessagePatternS, MessagePatternDHES},
	},
}

var HandshakeXN = HandshakePattern{
	Name: "XN",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE},
		{MessagePatternS, MessagePatternDHSE},
	},
}

var HandshakeIN = HandshakePattern{
	Name: "IN",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

var HandshakeXK = HandshakePattern{
	Name:                 "XK",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES},
		{MessagePatternE, MessagePatternDHEE},
		{MessagePatternS, MessagePatternDHSE},
	},
}

var HandshakeIK = HandshakePattern{
	Name:                 "IK",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternS, MessagePatternDHSS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

var HandshakeXX = HandshakePattern{
	Name: "XX",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternS, MessagePatternDHES},
		{MessagePatternS, MessagePatternDHSE},
	},
}

var HandshakeXXfallback = HandshakePattern{
	Name:                 "XXfallback",
	ResponderPreMessages: []MessagePattern{MessagePatternE},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHEE, MessagePatternS, MessagePatternDHSE},
		{MessagePatternS, MessagePatternDHES},
	},
}

var HandshakeIX = HandshakePattern{
	Name: "IX",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE, MessagePatternS, MessagePatternDHES},
	},
}

var HandshakeN = HandshakePattern{
	Name:                 "N",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES},
	},
}

var HandshakeK = HandshakePattern{
	Name:                 "K",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternDHSS},
	},
}

var HandshakeX = HandshakePattern{
	Name:                 "X",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternS, MessagePatternDHSS},
	},
}

var HandshakeXXhfs = HandshakePattern{
	Name: "XXhfs",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1, MessagePatternS, MessagePatternDHES},
		{MessagePatternS, MessagePatternDHSE},
	},
}

var HandshakeNNhfs = HandshakePattern{
	Name: "NNhfs",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1},
	},
}

var HandshakeKNhfs = HandshakePattern{
	Name:                 "KNhfs",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1, MessagePatternDHSE},
	},
}

var HandshakeNKhfs = HandshakePattern{
	Name:                 "NKhfs",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1, MessagePatternDHES},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1},
	},
}

var HandshakeKKhfs = HandshakePattern{
	Name:                 "KKhfs",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1, MessagePatternDHES, MessagePatternDHSS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1, MessagePatternDHSE},
	},
}

var HandshakeNXhfs = HandshakePattern{
	Name: "NXhfs",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1, MessagePatternS, MessagePatternDHES},
	},
}

var HandshakeKXhfs = HandshakePattern{
	Name:                 "KXhfs",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1, MessagePatternDHSE, MessagePatternS, MessagePatternDHES},
	},
}

var HandshakeXNhfs = HandshakePattern{
	Name: "XNhfs",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1},
		{MessagePatternS, MessagePatternDHSE},
	},
}

var HandshakeINhfs = HandshakePattern{
	Name: "INhfs",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1, MessagePatternS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1, MessagePatternDHSE},
	},
}

var HandshakeXKhfs = HandshakePattern{
	Name:                 "XKhfs",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1, MessagePatternDHES},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1},
		{MessagePatternS, MessagePatternDHSE},
	},
}

var HandshakeIKhfs = HandshakePattern{
	Name:                 "IKhfs",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1, MessagePatternDHES, MessagePatternS, MessagePatternDHSS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1, MessagePatternDHSE},
	},
}

var HandshakeIXhfs = HandshakePattern{
	Name: "IXhfs",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternE1, MessagePatternS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternEKEM1, MessagePatternDHSE, MessagePatternS, MessagePatternDHES},
	},
}
