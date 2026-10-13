# Step 5: workload

Script: `bash 05-workload/workload.sh` lists and scans the images of the namespace `WL_NS` into `$WORK/workload`.
## 5. Workload

The workload images are already in the downstream list of section 4. This section produces a separate SBOM of the workload alone, the one a customer extends and hands over for their own application. Same commands restricted to the workload namespaces:

```bash
export KUBECONFIG="$WORK/downstream/kubeconfig"
cd "$WORK/workload"
WL_NS=my-app
kubectl -n "$WL_NS" get pods -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
```

Then the scan loop of section 3.3. The merge of section 6 accepts any subset of directories, so the workload SBOM can be merged alone or with the rest of the stack.

Observed, 2026-10-12: namespace `sample-workload`, deployment `web` with two replicas of `registry.suse.com/suse/nginx:1.27`, one pod per node; `all-images.txt` holds that one image and its scan returns 89 packages.

