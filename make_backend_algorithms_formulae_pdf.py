"""Generate the formula PDF from its matching Markdown reference."""
from make_backend_reference_pdf import ROOT, build_pdf

if __name__ == "__main__":
    build_pdf(ROOT / "docs" / "backend_algorithms_formulae_reference.md",
              title="Backend algorithms and formulae")
