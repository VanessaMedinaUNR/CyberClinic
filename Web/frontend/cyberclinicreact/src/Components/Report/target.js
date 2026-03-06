
export function TargetList ({targets}) {
    const list = Array.isArray(targets) ? targets : [];
    if (list.length === 0) return <span>N/A</span>;
    return (
        <span>
            {list.map((target, index) => (
                <span key={index}>
                    {target.target_name}
                    {target.target_value && target.target_value !== target.target_name ? ` (${target.target_value})` : ''}
                    {index < list.length - 1 ? ', ' : ''}
                </span>
            ))}
        </span>
    )
};

export function TargetTable ({targets}) {
    const list = Array.isArray(targets) ? targets : [];
    if (list.length === 0) return null;
    return (
        <table>
            <thead>
                <tr>
                    <th>Target Name</th>
                    <th>Target Address</th>
                    <th>Target Type</th>
                </tr>
            </thead>
            <tbody>
                {list.map((target, index) => (
                    <tr key={index}>
                        <td>{target.target_name}</td>
                        <td>{target.target_value}</td>
                        <td>{target.target_type}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    )
};