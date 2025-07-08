package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
)

type config struct {
	LogFile string `yaml:"logFile"`
}

type plugin struct {
	stub stub.Stub
	mask stub.EventMask //nolint:golint,unused
}

var (
	cfg config
	log *logrus.Logger
)

var (
	_ = (stub.ConfigureInterface)((*plugin)(nil))
	_ = (stub.SynchronizeInterface)((*plugin)(nil))
	_ = (stub.ShutdownInterface)((*plugin)(nil))
	_ = (stub.RunPodInterface)((*plugin)(nil))
	_ = (stub.StopPodInterface)((*plugin)(nil))
	_ = (stub.RemovePodInterface)((*plugin)(nil))
	_ = (stub.CreateContainerInterface)((*plugin)(nil))
	_ = (stub.PostCreateContainerInterface)((*plugin)(nil))
	_ = (stub.StartContainerInterface)((*plugin)(nil))
	_ = (stub.PostStartContainerInterface)((*plugin)(nil))
	_ = (stub.UpdateContainerInterface)((*plugin)(nil))
	_ = (stub.PostUpdateContainerInterface)((*plugin)(nil))
	_ = (stub.StopContainerInterface)((*plugin)(nil))
	_ = (stub.RemoveContainerInterface)((*plugin)(nil))
)

func (p *plugin) Configure(_ context.Context, config, runtime, version string) (stub.EventMask, error) {
	log.Infof("Connected to %s/%s...", runtime, version)

	if config == "" {
		return 0, nil
	}

	oldCfg := cfg
	err := yaml.Unmarshal([]byte(config), &cfg)
	if err != nil {
		return 0, fmt.Errorf("failed to parse provided configuration: %w", err)
	}

	if cfg.LogFile != oldCfg.LogFile {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Errorf("failed to open log file %q: %v", cfg.LogFile, err)
			return 0, fmt.Errorf("failed to open log file %q: %w", cfg.LogFile, err)
		}
		log.SetOutput(f)
	}
	log.Info("NRI plugin configured successfully")

	return 0, nil
}

func (p *plugin) Synchronize(_ context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	log.Infof("Synchronized state with the runtime (%d pods, %d containers)...",
		len(pods), len(containers))
	return nil, nil
}

func (p *plugin) Shutdown(_ context.Context) {
	log.Info("Runtime shutting down...")
}

func (p *plugin) RunPodSandbox(_ context.Context, pod *api.PodSandbox) error {
	log.Infof("Started pod %s/%s...", pod.GetNamespace(), pod.GetName())
	return nil
}

func (p *plugin) StopPodSandbox(_ context.Context, pod *api.PodSandbox) error {
	log.Infof("Stopped pod %s/%s...", pod.GetNamespace(), pod.GetName())
	return nil
}

func (p *plugin) RemovePodSandbox(_ context.Context, pod *api.PodSandbox) error {
	log.Infof("Removed pod %s/%s...", pod.GetNamespace(), pod.GetName())
	return nil
}

func (p *plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	log.Infof("Creating container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())

	//
	// This is the container creation request handler. Because the container
	// has not been created yet, this is the lifecycle event which allows you
	// the largest set of changes to the container's configuration, including
	// some of the later immutable parameters. Take a look at the adjustment
	// functions in pkg/api/adjustment.go to see the available controls.
	//
	// In addition to reconfiguring the container being created, you are also
	// allowed to update other existing containers. Take a look at the update
	// functions in pkg/api/update.go to see the available controls.
	//

	adjustment := &api.ContainerAdjustment{}
	updates := []*api.ContainerUpdate{}

	return adjustment, updates, nil
}

func (p *plugin) PostCreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	log.Infof("Created container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) StartContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	log.Infof("Starting container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) PostStartContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	log.Infof("Started container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) UpdateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container, _ *api.LinuxResources) ([]*api.ContainerUpdate, error) {
	log.Infof("Updating container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())

	//
	// This is the container update request handler. You can make changes to
	// the container update before it is applied. Take a look at the functions
	// in pkg/api/update.go to see the available controls.
	//
	// In addition to altering the pending update itself, you are also allowed
	// to update other existing containers.
	//

	updates := []*api.ContainerUpdate{}

	return updates, nil
}

func (p *plugin) PostUpdateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	log.Infof("Updated container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) StopContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) ([]*api.ContainerUpdate, error) {
	log.Infof("Stopped container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())

	//
	// This is the container (post-)stop request handler. You can update any
	// of the remaining running containers. Take a look at the functions in
	// pkg/api/update.go to see the available controls.
	//

	return []*api.ContainerUpdate{}, nil
}

func (p *plugin) RemoveContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	log.Infof("Removed container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) onClose() {
	log.Info("Connection to the runtime lost, exiting...")
	os.Exit(0)
}

func main() {
	var (
		pluginName string
		pluginIdx  string
		err        error
	)

	log = logrus.StandardLogger()
	log.SetFormatter(&logrus.TextFormatter{
		PadLevelText: true,
	})

	flag.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	flag.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	flag.StringVar(&cfg.LogFile, "log-file", "", "logfile name, if logging to a file")
	flag.Parse()

	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("failed to open log file %q: %v", cfg.LogFile, err)
		}
		log.SetOutput(f)
	}

	p := &plugin{}
	opts := []stub.Option{
		stub.WithOnClose(p.onClose),
	}
	if pluginName != "" {
		opts = append(opts, stub.WithPluginName(pluginName))
	}
	if pluginIdx != "" {
		opts = append(opts, stub.WithPluginIdx(pluginIdx))
	}

	if p.stub, err = stub.New(p, opts...); err != nil {
		log.Fatalf("failed to create plugin stub: %v", err)
	}

	if err = p.stub.Run(context.Background()); err != nil {
		log.Error(fmt.Sprintf("plugin exited (%v)", err))
		os.Exit(1)
	}
}
