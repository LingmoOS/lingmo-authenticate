package authcommon

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/procfs"
)

func ReadFileLines(filepath string) ([]string, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	return lines, nil
}

func GetExecPath(s *dbusutil.Service, sender string) (string, error) {
	pid, err := s.GetConnPID(sender)
	if err != nil {
		return "", err
	}
	exe, err := procfs.Process(pid).Exe()
	if err != nil {
		// 当文件被删除的时候无法获取的路径，需通过自定义的函数获取exe文件指向的文件路径
		// 如果文件被删除了，返回的文件路径中会包含(deleted), 例如：/usr/bin/dde-lock (deleted)，将多余的字符去掉，截留/usr/bin/dde-lock并返回
		pErr, ok := err.(*os.PathError)
		if ok {
			if os.IsNotExist(pErr.Err) {
				exe := strings.Replace(pErr.Path, " (deleted)", "", -1)
				return exe, nil
			}
		}
	}

	return exe, nil
}
