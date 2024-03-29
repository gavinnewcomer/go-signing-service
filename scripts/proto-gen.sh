echo "Generating proto code"
cd proto
proto_dirs=$(find . -path -prune -o -name '*.proto' -print0 | xargs -0 -n1 dirname | sort | uniq)
for dir in $proto_dirs; do
  for file in $(find "${dir}" -maxdepth 1 -name '*.proto'); do
    if grep go_package $file &>/dev/null; then
      buf generate --template buf.gen.yaml $file
    fi
  done
done

# move proto files to the right places
cp -R github.com/skip-mev/platform-take-home/types ../
rm -rf github.com
