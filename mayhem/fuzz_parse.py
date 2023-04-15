#!/usr/bin/env python3

import atheris
import sys
import networkx as nx
import fuzz_helpers as fh

with atheris.instrument_imports(include=['pysmiles']):
    import pysmiles


def TestOneInput(data):
    fdp = fh.EnhancedFuzzedDataProvider(data)
    should_read = fdp.ConsumeBool()
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
    except nx.NetworkXError:
        return -1
    except ValueError as e:
        if any((s for s in
                ['Edge specified by marker', 'is malformatted', 'specifies a bond between an atom and itself',
                 'Conflicting bond orders for ring between indices', 'A hydrogen atom', 'Overwritten by',
                 'before an atom', 'You specified an aromatic atom outside of a'] if s in str(e))):
            return -1
        raise e
    except KeyError as e:
        if 'ring' in str(e):
            return -1
        raise e
    except IndexError:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
