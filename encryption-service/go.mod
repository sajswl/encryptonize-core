module encryption-service

go 1.16

require (
	github.com/aws/aws-sdk-go v1.35.15
	github.com/gofrs/uuid v3.2.0+incompatible
	github.com/golang/protobuf v1.4.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.2
	github.com/jackc/pgtype v1.5.0
	github.com/jackc/pgx/v4 v4.9.0
	github.com/knadh/koanf v0.15.0
	github.com/sirupsen/logrus v1.7.0
	github.com/sony/gobreaker v0.4.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	google.golang.org/genproto v0.0.0-20200904004341-0bd0a958aa1d // indirect
	google.golang.org/grpc v1.33.2
	google.golang.org/grpc/examples v0.0.0-20201110215615-b5d479d642af // indirect
	google.golang.org/protobuf v1.25.0
)
