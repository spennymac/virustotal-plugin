package ipc

//Composer composes a Message
type Composer interface {
	Compose() (*Message, error)
}

//Decomposer decomposes a Message
type Decomposer interface {
	Decompose() (*Message, error)
}

//Message provide type information for
//data that is sent by a Producer and consumer
//by a Consumer
type Message struct {
	Type string `json:"type"` //type of message
	Body []byte `json:"body"` //raw message
}

//Connector connects to messaging system
type Connector interface {
	Connect() error
}

//Consumer connects and consumes messages from
//the messaging system
type Consumer interface {
	Connector
	Consume() <-chan Decomposer
}

//Producer connects and produces messages to
//the messaging system
type Producer interface {
	Connector
	Produce(Composer) error
}
