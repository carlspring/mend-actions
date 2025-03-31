This is a set of Github Actions for the Mend.io CLI.

# List of Actions

## The `setup` Action

This Github Action is responsible for downloading and installing the Mend.io CLI.

Please note:
* This action is required to be run before any other Mend.io CLI actions.
* The version of the Mend.io CLI to be installed will be the latest available version from Mend.io, as the vendor
  does not provide a versioned download link, nor do they provide historical versions.

## The `login` Action

This Github Action is responsible for logging in to the Mend.io website.

This action requires the following environment variables to be set in the invoking Github workflow in order to
be able to authenticate securely without storing the credentials on the file system:

```yaml
env:
  MEND_URL: ${{ secrets.MEND_URL }}
  MEND_ORGANIZATION: ${{ secrets.MEND_ORGANIZATION }}
  MEND_ORGANIZATION_KEY: ${{ secrets.MEND_ORGANIZATION_KEY }}
  MEND_USER_KEY: ${{ secrets.MEND_USER_KEY }}
  MEND_EMAIL: ${{ secrets.MEND_EMAIL }}
```

Needless to say, the above secrets must also be defined as GitHub secrets in the repository settings.

## The `scan-dependencies` Action

This Github Action is responsible for carrying out a dependency scan and producing a report.

The following options are available:

| Input Parameter      | Description                                    | Default Value         | Required |
|----------------------|------------------------------------------------|-----------------------|----------|
| `json_filename`      | The JSON output filename for the scan results  | `dependencies.json`   | false    |
| `sarif_filename`     | The SARIF output filename for the scan results | `results.sarif`       | false    |
| `scope`              | The scope for the scan results                 | n/a                   | true     |
| `github_url`         | The URL for the GitHub repository              | `https://github.com`  | true     |
| `github_repository`  | The name of the GitHub repository              | n/a                   | false    |
| `publish_to_mend`    | Whether to publish the scan results to Mend.io | `true`                | true     |
| `workflow_run`       | The ID of the workflow run                     | n/a                   | true     |

## The `scan-docker` Action

This Github Action is responsible for carrying out a Docker image scan and producing a report.

The following options are available:

| Input Parameter      | Description                                          | Default Value      | Required |
|----------------------|------------------------------------------------------|--------------------|----------|
| `docker-image`       | The Docker image to scan                             | n/a                | true     |
| `exclude-licensing`  | Exclude licensing information from the scan results  | `false`            | false    |
| `format`             | The format for the scan results                      | `sarif`            | false    |
| `filename`           | The filename for the scan results                    | `results.sarif`    | false    |
| `scope`              | The scope for the scan results                       | n/a                | true     |
