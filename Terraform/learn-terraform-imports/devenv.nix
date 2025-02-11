{ inputs, pkgs, ... }:

{
  git-hooks.hooks = {
    # lint shell scripts
    shellcheck.enable = true;
    # execute example shell from Markdown files
    mdsh.enable = true;
    # lint GitHub Actions workflows
    actionlint.enable = true;
    # lint Ansible
    ansible-lint.enable = true;
    # lint Terraform
    tflint.enable = true;
  };

    # Env vars
    dotenv.enable = true;

    # Tools
    packages = [
    pkgs.aws-vault
    pkgs.trivy
    ];


    # Languages used
    # Ansible
    languages.ansible.enable = true;

    # Terraform
    languages.terraform = {
      enable = true;
      version = "1.10";
    };
}