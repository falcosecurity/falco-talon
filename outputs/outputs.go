package outputs

import (
	"fmt"

	aws "github.com/falco-talon/falco-talon/internal/aws/client"
	"github.com/falco-talon/falco-talon/internal/events"
	minio "github.com/falco-talon/falco-talon/internal/minio/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	awss3Out "github.com/falco-talon/falco-talon/outputs/aws/s3"
	"github.com/falco-talon/falco-talon/outputs/file"
	minioOut "github.com/falco-talon/falco-talon/outputs/minio"

	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Output struct {
	Output          func(*rules.Output, *model.Data) (utils.LogLine, error)
	CheckParameters func(*rules.Output) error
	Init            func() error
	Name            string
	Category        string
	Checks          []checkOutput
}

type Outputs []*Output

type checkOutput func(output *rules.Output, event *events.Event) error

var availableOutputs *Outputs
var enabledOutputs *Outputs

func init() {
	availableOutputs = new(Outputs)
	availableOutputs = GetDefaultOutputs()
	enabledOutputs = new(Outputs)
}

func GetDefaultOutputs() *Outputs {
	if availableOutputs == nil {
		availableOutputs = new(Outputs)
	}
	if len(*availableOutputs) == 0 {
		availableOutputs.Add(
			&Output{
				Category:        "local",
				Name:            "file",
				Init:            nil,
				CheckParameters: file.CheckParameters,
				Checks: []checkOutput{
					file.CheckFolderExist,
				},
				Output: file.Output,
			},
			&Output{
				Category:        "minio",
				Name:            "s3",
				Init:            minio.Init,
				CheckParameters: minioOut.CheckParameters,
				Checks: []checkOutput{
					minioOut.CheckBucketExist,
				},
				Output: minioOut.Output,
			},
			&Output{
				Category:        "aws",
				Name:            "s3",
				Init:            aws.Init,
				CheckParameters: awss3Out.CheckParameters,
				Output:          awss3Out.Output,
			},
		)
	}

	return availableOutputs
}

func (outputs *Outputs) Add(output ...*Output) {
	*outputs = append(*outputs, output...)
}

func GetOutputs() *Outputs {
	return enabledOutputs
}

func (outputs *Outputs) FindOutput(fullname string) *Output {
	if outputs == nil {
		return nil
	}

	for _, i := range *outputs {
		if i == nil {
			continue
		}
		if fullname == fmt.Sprintf("%v:%v", i.Category, i.Name) {
			return i
		}
	}
	return nil
}

func Init() error {
	rules := rules.GetRules()

	categories := map[string]bool{}
	enabledCategories := map[string]bool{}

	// list actionner categories to init
	for _, i := range *rules {
		for _, j := range i.Actions {
			if j.GetOutput() != nil {
				if o := GetDefaultOutputs().FindOutput(j.GetOutput().Target); o != nil {
					categories[o.GetCategory()] = true
				}
			}
		}
	}

	for category := range categories {
		for _, output := range *availableOutputs {
			if category == output.Category {
				if output.Init != nil {
					utils.PrintLog("info", utils.LogLine{Message: "init", OutputCategory: output.Category})
					if err := output.Init(); err != nil {
						utils.PrintLog("error", utils.LogLine{Message: "init", Error: err.Error(), OutputCategory: output.Category})
						return err
					}
					enabledCategories[category] = true
				}
				break // we break to avoid to repeat the same init() several times
			}
		}
	}

	for i := range enabledCategories {
		for _, j := range *availableOutputs {
			if i == j.Category {
				enabledOutputs.Add(j)
			}
		}
	}

	return nil
}

func (output *Output) GetFullName() string {
	return output.Category + ":" + output.Name
}

func (output *Output) GetName() string {
	return output.Name
}

func (output *Output) GetCategory() string {
	return output.Category
}
