"""Lockfile parsers for every supported tech stack, all producing the same Graph."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from app.graph import Graph
from app.stacks import dotnet, go, java, php, pnpm, python, ruby, rust, yarn
from app.stacks.base import Builder


@dataclass(frozen=True)
class Stack:
    id: str
    ecosystem: str
    language: str
    lockfile: str
    manifests: tuple[str, ...]
    loader: Callable[[Path], Builder] | None
    fix_hint: str

    def present(self, d: Path) -> bool:
        if self.id == "pip":
            return any(python.requirement_files(d))
        return any(d.glob(self.lockfile))

    def manifest_in(self, d: Path) -> bool:
        return any(any(d.glob(m)) for m in self.manifests)

    def load(self, root: Path) -> Graph:
        assert self.loader is not None
        g = self.loader(root).graph()
        g.lockfile_name = self.lockfile
        return g


STACKS = (
    Stack("npm", "npm", "Node.js", "package-lock.json", ("package.json",), None,
          "Run `npm install --package-lock-only` and include package-lock.json."),
    Stack("yarn", "npm", "Node.js", "yarn.lock", ("package.json",), yarn.load_yarn,
          "Run `yarn install` and include yarn.lock."),
    Stack("pnpm", "npm", "Node.js", "pnpm-lock.yaml", ("package.json",), pnpm.load_pnpm,
          "Run `pnpm install --lockfile-only` and include pnpm-lock.yaml."),
    Stack("uv", "PyPI", "Python", "uv.lock", ("pyproject.toml",), python.load_uv,
          "Run `uv lock`."),
    Stack("poetry", "PyPI", "Python", "poetry.lock", ("pyproject.toml",), python.load_poetry,
          "Run `poetry lock`."),
    Stack("pipenv", "PyPI", "Python", "Pipfile.lock", ("Pipfile",), python.load_pipfile,
          "Run `pipenv lock`."),
    Stack("pip", "PyPI", "Python", "requirements.txt",
          ("pyproject.toml", "setup.py", "setup.cfg"), python.load_requirements,
          "Include a lockfile (uv.lock, poetry.lock, Pipfile.lock) or a pinned "
          "requirements.txt (`pip freeze > requirements.txt`)."),
    Stack("go", "Go", "Go", "go.mod", ("go.mod",), go.load_gomod, "Run `go mod tidy`."),
    Stack("cargo", "crates.io", "Rust", "Cargo.lock", ("Cargo.toml",), rust.load_cargo,
          "Run `cargo generate-lockfile` and include Cargo.lock."),
    Stack("composer", "Packagist", "PHP", "composer.lock", ("composer.json",),
          php.load_composer, "Run `composer update --lock` and include composer.lock."),
    Stack("bundler", "RubyGems", "Ruby", "Gemfile.lock", ("Gemfile",), ruby.load_gemfile,
          "Run `bundle lock` and include Gemfile.lock."),
    Stack("nuget", "NuGet", ".NET", "packages.lock.json", ("*.csproj", "*.fsproj"),
          dotnet.load_nuget,
          "Set <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>, run "
          "`dotnet restore` and include packages.lock.json."),
    Stack("gradle", "Maven", "Java", "gradle.lockfile",
          ("build.gradle", "build.gradle.kts", "pom.xml"), java.load_gradle,
          "Enable Gradle dependency locking (`./gradlew dependencies --write-locks`) and "
          "include gradle.lockfile; plain pom.xml versions are not resolved."),
)
BY_ID = {s.id: s for s in STACKS}
LANGUAGES = list(dict.fromkeys(s.language for s in STACKS))


def found_in(d: Path) -> list[Stack]:
    """Lockfile-backed stacks in one directory, at most one per language (best lock first)."""
    out, langs = [], set()
    for s in STACKS:
        if s.language not in langs and s.present(d):
            out.append(s)
            langs.add(s.language)
    return out


def unlocked_in(d: Path) -> list[Stack]:
    """Languages with a manifest here but no lockfile we can read."""
    have = {s.language for s in found_in(d)}
    out, langs = [], set()
    for s in reversed(STACKS):
        if s.language not in have and s.language not in langs and s.manifest_in(d):
            out.append(s)
            langs.add(s.language)
    return out[::-1]
