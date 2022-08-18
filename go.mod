module github.com/psanford/lambda-ssh-ca

go 1.18

require (
	github.com/aws/aws-lambda-go v1.34.1
	github.com/aws/aws-sdk-go v1.44.76
	github.com/inconshreveable/log15 v0.0.0-20201112154412-8562bdadbbac
	github.com/psanford/lambdahttp v0.0.0-20210423045543-144d41bdd39e
	github.com/psanford/logmiddleware v0.0.0-20210423045917-73776f848da2
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
)

require (
	github.com/felixge/httpsnoop v1.0.1 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
)


replace github.com/psanford/lambdahttp => /home/psanford/projects/lambdahttp
