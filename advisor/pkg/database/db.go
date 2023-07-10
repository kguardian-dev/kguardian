package db

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type PodTraffic struct {
	UUID         string
	SrcPodName   string
	SrcIP        string
	SrcNamespace string
	DstPodName   string
	DstIP        string
	DstNamespace string
	TimeStamp    string
}

type PodSpec struct {
	UUID      string
	Name      string
	Namespace string
	Spec      map[string]interface{}
}

type DBConnection struct {
	db *sql.DB
}

type PodTrafficGetter interface {
	GetPodTraffic(uuid string) (*PodTraffic, error)
	GetPodSpec(name string) (*PodSpec, error)
}

type PodTrafficStub struct{}

func NewDBConnection(host string, port int, user string, password string, dbname string) (*DBConnection, error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return &DBConnection{db: db}, nil
}

func (dbc *DBConnection) Close() error {
	return dbc.db.Close()
}

func (dbc *DBConnection) GetPodTraffic(podName string) (*PodTraffic, error) {
	row := dbc.db.QueryRow("SELECT * FROM pod_traffic WHERE pod_name = $1", podName)

	podTraffic := new(PodTraffic)
	err := row.Scan(&podTraffic.UUID, &podTraffic.SrcPodName, &podTraffic.SrcIP, &podTraffic.SrcNamespace,
		&podTraffic.DstPodName, &podTraffic.DstIP, &podTraffic.DstNamespace, &podTraffic.TimeStamp)
	if err != nil {
		if err == sql.ErrNoRows {
			// There were no rows, but otherwise no error occurred
			return nil, nil
		}
		return nil, err
	}

	return podTraffic, nil
}

func (dbc *DBConnection) GetPodSpec(name string) (*PodSpec, error) {
	row := dbc.db.QueryRow("SELECT * FROM pod_spec WHERE name = $1", name)

	podSpec := new(PodSpec)
	err := row.Scan(&podSpec.UUID, &podSpec.Name, &podSpec.Namespace)
	if err != nil {
		if err == sql.ErrNoRows {
			// There were no rows, but otherwise no error occurred
			return nil, nil
		}
		return nil, err
	}

	// You may need a separate query to get the 'spec' column, depending on its type in the database
	// For this example, I'm leaving it as an empty map
	podSpec.Spec = make(map[string]interface{})

	return podSpec, nil
}

func (pts *PodTrafficStub) GetPodTraffic(podName string) (*PodTraffic, error) {
	// Return dummy data, or whatever is appropriate for your use case
	return &PodTraffic{
		UUID:         "example-uuid",
		SrcPodName:   podName,
		SrcIP:        "0.0.0.0",
		SrcNamespace: "default",
		DstPodName:   "dummy-dst-pod",
		DstIP:        "0.0.0.0",
		DstNamespace: "default",
		TimeStamp:    "2023-07-15T15:04:05Z",
	}, nil
}

func (pts *PodTrafficStub) GetPodSpec(name string) (*PodSpec, error) {
	// Return dummy data, or whatever is appropriate for your use case
	return &PodSpec{
		UUID:      "dummy-uuid",
		Name:      name,
		Namespace: "default",
		Spec:      make(map[string]interface{}),
	}, nil
}
