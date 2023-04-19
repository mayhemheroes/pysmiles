#!/usr/bin/env python3
import io
from contextlib import contextmanager
import random

import atheris
import sys
import fuzz_helpers as fh
import networkx as nx

with atheris.instrument_imports():
    import pysmiles


@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr


def exception_handler(exception: Exception) -> int:
    if random.random() > 0.995:
        return -1
    if isinstance(exception, nx.NetworkXError):
        return -1
    if isinstance(exception, ValueError) and any((s for s in ['Edge specified by marker', 'is malformatted',
                                                              'specifies a bond between an atom and itself',
                                                              'Conflicting bond orders for ring between indices',
                                                              'A hydrogen atom', 'Overwritten by',
                                                              'before an atom',
                                                              'You specified an aromatic atom outside of a'] if
                                                  s in str(exception))):
        return -1
    if isinstance(exception, KeyError) and 'ring' in str(exception):
        return -1
    raise exception



@atheris.instrument_func
def TestOneInput(data):
    fdp = fh.EnhancedFuzzedDataProvider(data)
    should_read = fdp.ConsumeBool()
    with nostdout():
        try:
            if should_read:
                res = pysmiles.read_smiles(fdp.ConsumeRandomString(),
                                           explicit_hydrogen=fdp.ConsumeBool(),
                                           zero_order_bonds=fdp.ConsumeBool(),
                                           reinterpret_aromatic=fdp.ConsumeBool())
                list(res.nodes)
            else:
                mol = nx.Graph()
                mol.add_edges_from(fh.build_fuzz_list(fdp, [tuple, int]))
                pysmiles.write_smiles(mol)
                pysmiles.fill_valence(mol, respect_hcount=fdp.ConsumeBool(),
                                      respect_bond_order=fdp.ConsumeBool(),
                                      max_bond_order=fdp.ConsumeIntInRange(0, 10))
        except Exception as e:
            exception_handler(e)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
