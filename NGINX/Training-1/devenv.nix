{ pkgs, lib, config, inputs, ... }:

{
  name = "nginx-devenv";
  dotenv.enable = true;
  # https://devenv.sh/basics/
  env.GREET = "devenv";

  # https://devenv.sh/packages/
  packages = [ pkgs.git pkgs.nginx pkgs.docker-compose pkgs.docker];

  #processes.serve.exec = "docker compose up";
  
  # https://devenv.sh/languages/
  # languages.rust.enable = true;
  #  languages.javascript.enable = true;
  #  languages.javascript.package = pkgs.nodejs;

  #  languages.javascript.yarn.enable = true;
  #  languages.javascript.yarn.package = pkgs.yarn;
  #  languages.javascript.yarn.install.enable = true;

  # https://devenv.sh/processes/
  # processes.cargo-watch.exec = "cargo-watch";

  # https://devenv.sh/services/
  #services = {
  #  nginx = {
  #    enable = true;
  #    package = pkgs.nginx;
  #httpConfig = (builtins.readFile ./default.conf.template);
  #};
  #};

  # https://devenv.sh/scripts/
  #scripts.hello.exec = ''
  #  echo hello from $GREET
  #'';

  #enterShell = ''
  #  hello
  #  git --version
  #'';

  # https://devenv.sh/tasks/
  # tasks = {
  #   "myproj:setup".exec = "mytool build";
  #   "devenv:enterShell".after = [ "myproj:setup" ];
  # };

  # https://devenv.sh/tests/
  #enterTest = ''
  #  echo "Running tests"
  #  git --version | grep --color=auto "${pkgs.git.version}"
  #  nginx -v
  #'';

  # https://devenv.sh/pre-commit-hooks/

  # See full reference at https://devenv.sh/reference/options/
}
