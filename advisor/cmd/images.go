package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/spf13/cobra"
)

// imagesCmd groups the read-only image inventory views. Nothing under
// `images` changes the cluster.
var imagesCmd = &cobra.Command{
	Use:     "images",
	Aliases: []string{"image"},
	Short:   "List the image digests your workloads run",
	Long: `Read-only views over the broker's image inventory: every image digest a
workload container has run, keyed by digest rather than tag, and which
workloads run it now.

  list   one page of the inventory (filter by namespace or repository)
  get    one digest and the workload containers that run or ran it

The inventory records identity only. It carries no vulnerability, SBOM or
signature data, so an image listed here is neither vetted nor flagged.`,
}

var (
	imagesListRepository string
	imagesListLimit      int
	imagesListAfter      string
	imagesListOutput     string
	imagesGetOutput      string
)

var imagesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List image digests in the inventory",
	Long: `List one page of the image inventory, ordered by digest.

RUNNING is the number of workload containers running the digest now; 0 means
it is no longer running and is kept until retention prunes it. When more
pages exist the command prints the --after cursor for the next page on
stderr.

Examples:
  kubectl kguardian images list
  kubectl kguardian images list -n payments
  kubectl kguardian images list --repository docker.io/library/nginx -o json`,
	Args: cobra.NoArgs,
	RunE: runImagesList,
}

var imagesGetCmd = &cobra.Command{
	Use:   "get <digest>",
	Short: "Show one image digest and the workloads that run it",
	Long: `Show one image digest (sha256:<hex>) and every workload container that runs
or ran it, running rows first.

Examples:
  kubectl kguardian images get sha256:0123...
  kubectl kguardian images get sha256:0123... -o yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runImagesGet,
}

func init() {
	rootCmd.AddCommand(imagesCmd)
	imagesCmd.AddCommand(imagesListCmd)
	imagesCmd.AddCommand(imagesGetCmd)
	imagesListCmd.Flags().StringVar(&imagesListRepository, "repository", "", "Only this normalised repository, e.g. docker.io/library/nginx")
	imagesListCmd.Flags().IntVar(&imagesListLimit, "limit", 100, "Page size (the broker caps it at 500)")
	imagesListCmd.Flags().StringVar(&imagesListAfter, "after", "", "Cursor: the digest printed as the next-page cursor by the previous call")
	imagesListCmd.Flags().StringVarP(&imagesListOutput, "output", "o", "table", "Output format: table, json or yaml")
	imagesGetCmd.Flags().StringVarP(&imagesGetOutput, "output", "o", "table", "Output format: table, json or yaml")
}

// explicitNamespace returns -n only when the user passed it: the kubeconfig
// context's default namespace must not silently narrow a cluster-wide view.
func explicitNamespace(cmd *cobra.Command) string {
	if cmd.Flags().Changed("namespace") {
		ns, _ := cmd.Flags().GetString("namespace")
		return ns
	}
	return ""
}

func runImagesList(cmd *cobra.Command, _ []string) error {
	output, err := parseOutput(imagesListOutput, "table", "json", "yaml")
	if err != nil {
		return err
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	opts := api.ImageListOptions{
		Namespace:  explicitNamespace(cmd),
		Repository: imagesListRepository,
		Limit:      imagesListLimit,
		After:      imagesListAfter,
	}
	return fetchAndRenderImages(opts, output, os.Stdout, os.Stderr)
}

func runImagesGet(cmd *cobra.Command, args []string) error {
	output, err := parseOutput(imagesGetOutput, "table", "json", "yaml")
	if err != nil {
		return err
	}
	digest := strings.TrimSpace(args[0])
	if !strings.HasPrefix(digest, "sha256:") && !strings.HasPrefix(digest, "sha512:") {
		return fmt.Errorf("digest must look like sha256:<hex>, got %q", digest)
	}
	closeFn, err := connectBroker(cmd)
	if err != nil {
		return err
	}
	defer closeFn()
	return fetchAndRenderImage(digest, output, os.Stdout)
}

// fetchAndRenderImages is the testable core of `images list`.
func fetchAndRenderImages(opts api.ImageListOptions, output string, w, errw io.Writer) error {
	page, raw, err := api.GetImages(opts)
	if err != nil {
		return brokerReadErr("fetching image inventory", err)
	}
	if output != "table" {
		return writeRaw(w, raw, output)
	}
	if len(page.Items) == 0 {
		_, err := fmt.Fprintln(w, "No images in the inventory.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "DIGEST\tREPOSITORY\tTAGS\tRUNNING\tLAST SEEN"); err != nil {
		return err
	}
	for _, im := range page.Items {
		tags := "-"
		if len(im.Tags) > 0 {
			tags = strings.Join(im.Tags, ",")
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			shortDigest(im.Digest), cell(orDash(im.Repository)), cell(tags),
			strconv.FormatInt(im.RunningContainers, 10), im.LastSeen); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if page.NextAfter != nil && *page.NextAfter != "" {
		_, err := fmt.Fprintf(errw, "More images: pass --after %s for the next page.\n", *page.NextAfter)
		return err
	}
	return nil
}

// fetchAndRenderImage is the testable core of `images get`.
func fetchAndRenderImage(digest, output string, w io.Writer) error {
	img, raw, err := api.GetImage(digest)
	if errors.Is(err, api.ErrNotFound) {
		return fmt.Errorf("image %s is not in the inventory", digest)
	}
	if err != nil {
		return brokerReadErr(fmt.Sprintf("fetching image %s", digest), err)
	}
	if output != "table" {
		return writeRaw(w, raw, output)
	}
	tags := "-"
	if len(img.Tags) > 0 {
		tags = strings.Join(img.Tags, ", ")
	}
	if _, err := fmt.Fprintf(w, "Digest:      %s\nRepository:  %s\nTags:        %s\nDigest kind: %s\nFirst seen:  %s\nLast seen:   %s\n\n",
		img.Digest, orDash(img.Repository), tags, img.DigestKind, img.FirstSeen, img.LastSeen); err != nil {
		return err
	}
	if len(img.Workloads) == 0 {
		_, err := fmt.Fprintln(w, "No workload containers recorded for this digest.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAMESPACE\tWORKLOAD\tCONTAINER\tRUNNING\tSTATE\tLAST SEEN"); err != nil {
		return err
	}
	for _, u := range img.Workloads {
		state := orDash(u.State)
		if u.StateReason != nil && *u.StateReason != "" {
			state += " (" + *u.StateReason + ")"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s/%s\t%s\t%t\t%s\t%s\n",
			u.Namespace, u.WorkloadKind, u.WorkloadName, u.ContainerName, u.Running, cell(state), u.LastSeen); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if img.Truncated {
		_, err := fmt.Fprintln(w, "\nMore workload containers run this digest than the broker lists (500).")
		return err
	}
	return nil
}
